import json
import boto3
import sqlite3

conn = sqlite3.connect("events.sqlite3", detect_types=sqlite3.PARSE_DECLTYPES)


def import_events(target_bucket="external-vpc-flow-logs-a"):
    curs = conn.cursor()
    s3 = boto3.client("s3")

    key_list = get_all_keys(target_bucket)
    for idx, key in enumerate(key_list):
        sys.stdout.write("\rKey: %s/%s\t" % (idx, len(key_list)))
        sys.stdout.flush()

        resp = s3.get_object(Bucket=target_bucket, Key=key)

        event_list = [e for e in resp["Body"].read().decode().split("\n")]
        for event in event_list:
            curs.execute("insert into events (eni, event) values (?, ?)", (key, event))

    conn.commit()
    curs.close()
    print("\nDone!")


def load_events_into_mem():
    print("Loading events into memory")
    curs = conn.cursor()
    events_by_eni = {}

    curs.execute("select eni, event from events")
    resp = curs.fetchall()

    for row in resp:
        eni, event = row

        try:
            events_by_eni[eni].append(json.loads(event))
        except KeyError:
            events_by_eni[eni] = [json.loads(event)]

    print("Done")
    curs.close()
    return events_by_eni


def load_events_into_mem_by_eni(eni_list):
    print("Loading events into memory")
    curs = conn.cursor()
    events_by_eni = {}

    curs.execute(
        "select eni, event from events where eni in (%s)"
        % (",".join(["?" for i in range(len(eni_list))])),
        eni_list,
    )
    resp = curs.fetchall()

    for row in resp:
        eni, event = row

        try:
            events_by_eni[eni].append(json.loads(event))
        except KeyError:
            events_by_eni[eni] = [json.loads(event)]

    print("Done")
    curs.close()
    return events_by_eni


def filter_by_accept_only(event_list):
    # print('Filtering to ACCEPTed events')

    return [e for e in event_list if "ACCEPT" in e["message"]]


def filter_by_bidir_only(event_list):
    # print('Filtering to only bidirectional traffic')
    src = []
    dst = []
    new_event_list = []
    traffic_id_list = []

    for e in event_list:
        _, _, _, src_addr, dst_addr, src_port, dst_port, _, _, _, _, _, _, _ = e[
            "message"
        ].split(" ")

        src.append("%s:%s" % (src_addr, src_port))
        dst.append("%s:%s" % (dst_addr, dst_port))

    traffic_id_list = set(src) & set(dst)

    for e in event_list:
        _, _, _, src_addr, dst_addr, src_port, dst_port, _, _, _, _, _, _, _ = e[
            "message"
        ].split(" ")

        src = "%s:%s" % (src_addr, src_port)
        dst = "%s:%s" % (dst_addr, dst_port)

        if src in traffic_id_list and dst in traffic_id_list:
            new_event_list.append(e)

    return new_event_list


def get_traffic_count(event_list):
    traffic_id_count = {}
    ip_count = {}
    for e in event_list:
        version, account_id, interface_id, src_addr, dst_addr, src_port, dst_port, protocol, num_packets, num_bytes, start_time, end_time, action, log_status = e[
            "message"
        ].split(
            " "
        )

        a2b = "%s:%s" % (src_addr, src_port)
        b2a = "%s:%s" % (dst_addr, dst_port)

        try:
            traffic_id_count[a2b] += 1
        except KeyError:
            traffic_id_count[a2b] = 1

        try:
            traffic_id_count[b2a] += 1
        except KeyError:
            traffic_id_count[b2a] = 1

        try:
            ip_count[src_addr] += 1
        except KeyError:
            ip_count[src_addr] = 1

        try:
            ip_count[dst_addr] += 1
        except KeyError:
            ip_count[dst_addr] = 1

    return traffic_id_count, ip_count


def sort_events_by_traffic_id(events, ip_count):
    bidir_events = {}
    for e in events:
        _, _, _, src_addr, dst_addr, _, _, _, _, _, _, _, _, _ = e["message"].split(" ")

        if ip_count[src_addr] > ip_count[dst_addr]:
            traffic_id = "%s::%s" % (src_addr, dst_addr)
        else:
            traffic_id = "%s::%s" % (dst_addr, src_addr)

        try:
            bidir_events[traffic_id].append(e)
        except KeyError:
            bidir_events[traffic_id] = [e]

    return bidir_events


def load_and_build_enis(enis=None):
    if enis:
        num_enis = len(enis)
        events_by_eni = load_events_into_mem_by_eni(enis)
    else:
        events_by_eni = load_events_into_mem()
        num_enis = len(events_by_eni.keys())

    ret_data = {}

    for i, (eni, events) in enumerate(events_by_eni.items()):
        if eni not in ret_data:
            ret_data[eni] = {}

        events = filter_by_accept_only(events)
        events = filter_by_bidir_only(events)
        traffic_id_count, ip_count = get_traffic_count(events)
        bidir_events = sort_events_by_traffic_id(events, ip_count)
        ts_list = set([e["timestamp"] for e in events])

        for traffic_id, event_list in bidir_events.items():
            src, dst = traffic_id.split("::")

            src_bytes_all = []
            src_pkts_all = []
            dst_bytes_all = []
            dst_pkts_all = []
            src_ports = []
            dst_ports = []

            src_port_switch_event_intervals = []
            dst_port_switch_event_intervals = []
            src_port_switch_pkt_intervals = []
            dst_port_switch_pkt_intervals = []

            src_port_switch_pkt_interval = 0
            dst_port_switch_pkt_interval = 0
            src_port_switch_event_interval = 0
            dst_port_switch_event_interval = 0

            prev_src_port = -1
            prev_dst_port = -1

            for ts in ts_list:
                ts_events = [e["message"] for e in event_list if e["timestamp"] == ts]

                src_pkts = 0
                src_bytes = 0
                dst_pkts = 0
                dst_bytes = 0
                for e in ts_events:
                    version, account_id, interface_id, src_addr, dst_addr, src_port, dst_port, protocol, num_packets, num_bytes, start_time, end_time, action, log_status = e.split(
                        " "
                    )

                    # ignore everything that isn't tcp
                    if int(protocol) != 6:
                        continue

                    src_port = int(src_port)
                    dst_port = int(dst_port)
                    num_packets = int(num_packets)

                    if src_addr == src:
                        src_bytes += int(num_bytes)
                        src_pkts += int(num_packets)
                        src_ports.append(src_port)
                        dst_ports.append(dst_port)

                        if prev_src_port == -1:
                            prev_src_port = src_port
                        elif prev_src_port != src_port:
                            src_port_switch_event_intervals.append(
                                src_port_switch_event_interval
                            )
                            src_port_switch_pkt_intervals.append(
                                src_port_switch_pkt_interval
                            )

                            src_port_switch_event_interval = 0
                            src_port_switch_pkt_interval = 0
                        else:
                            src_port_switch_event_interval += 1
                            src_port_switch_pkt_interval += num_packets

                        if prev_dst_port == -1:
                            prev_dst_port = dst_port
                        elif prev_dst_port != dst_port:
                            dst_port_switch_event_intervals.append(
                                dst_port_switch_event_interval
                            )
                            dst_port_switch_pkt_intervals.append(
                                dst_port_switch_pkt_interval
                            )

                            dst_port_switch_event_interval = 0
                            dst_port_switch_pkt_interval = 0
                        else:
                            dst_port_switch_event_interval += 1
                            dst_port_switch_pkt_interval += num_packets

                    else:
                        dst_bytes += int(num_bytes)
                        dst_pkts += int(num_packets)
                        src_ports.append(dst_port)
                        dst_ports.append(src_port)

                        if prev_src_port == -1:
                            prev_src_port = dst_port
                        elif prev_src_port != dst_port:
                            src_port_switch_event_intervals.append(
                                src_port_switch_event_interval
                            )
                            src_port_switch_pkt_intervals.append(
                                src_port_switch_pkt_interval
                            )

                            src_port_switch_event_interval = 0
                            src_port_switch_pkt_interval = 0
                        else:
                            dst_port_switch_event_interval += 1
                            dst_port_switch_pkt_interval += num_packets

                        if prev_dst_port == -1:
                            prev_dst_port = src_port
                        elif prev_dst_port != src_port:
                            dst_port_switch_event_intervals.append(
                                dst_port_switch_event_interval
                            )
                            dst_port_switch_pkt_intervals.append(
                                dst_port_switch_pkt_interval
                            )

                            dst_port_switch_event_interval = 0
                            dst_port_switch_pkt_interval = 0
                        else:
                            src_port_switch_event_interval += 1
                            src_port_switch_pkt_interval += num_packets

                src_bytes_all.append(src_bytes)
                dst_bytes_all.append(dst_bytes)
                src_pkts_all.append(src_pkts)
                dst_pkts_all.append(dst_pkts)

            ret_data[eni][traffic_id] = (
                src_bytes_all,
                src_pkts_all,
                dst_bytes_all,
                dst_pkts_all,
                set(src_ports),
                set(dst_ports),
                src_port_switch_event_intervals,
                dst_port_switch_event_intervals,
                src_port_switch_pkt_intervals,
                dst_port_switch_pkt_intervals,
            )

    return ret_data

