import preprocess
import numpy as np

from scipy.spatial import ConvexHull

def build_hull():
    pool_ips = ["107.181.183.242", "45.76.15.201", "199.231.85.124"]

    mining_enis = [
        #'eni-6ac1e534-all', # ~14 hours of c4.large solo mining vrm
        #'eni-4211301c-all', # ~12 hours of c4.large pool mining vrm
        "eni-55aa820b-all",  # ~10 hours of c4.large pool mining xmr
        "eni-09706822-all",  # ~10 hours of c4.4xlarge pool mining xmr
        "eni-14f67843-all",  # ~24 hours of c4.8xlarge pool mining xmr
        "eni-3cf7796b-all",  # ~24 hours of c4.4xlarge pool mining xmr
        "eni-eadc17ba-all",  # ~24 hours of c4.2xlarge pool mining xmr
        "eni-76dd1626-all",  # ~24 hours of c4.xlarge pool mining xmr
        # eni-f2deedd8-all', # ~24 hours of c4.large pool mining xmr
    ]
    ret_data = preprocess.load_and_build_enis(enis=mining_enis)

    src_bytes_all = []
    src_pkts_all = []
    dst_bytes_all = []
    dst_pkts_all = []

    for eni, v in ret_data.items():
        for traffic_id, data in v.items():
            src, dst = traffic_id.split("::")
            if src not in pool_ips and dst not in pool_ips:
                continue

            src_bytes, src_pkts, dst_bytes, dst_pkts, src_ports, dst_ports, src_port_switch_event_intervals, dst_port_switch_event_intervals, src_port_switch_pkt_intervals, dst_port_switch_pkt_intervals = (
                data
            )

            src_bytes_all.extend(src_bytes)
            dst_bytes_all.extend(dst_bytes)
            src_pkts_all.extend(src_pkts)
            dst_pkts_all.extend(dst_pkts)

    src_bytes_all = np.asarray(src_bytes_all)
    dst_bytes_all = np.asarray(dst_bytes_all)
    src_pkts_all = np.asarray(src_pkts_all)
    dst_pkts_all = np.asarray(dst_pkts_all)

    mining_pts = np.column_stack(
        (src_bytes_all, src_pkts_all, dst_bytes_all, dst_pkts_all)
    )

    # lets just ignore (0,0,0,0)
    mining_pts = mining_pts[~np.all(mining_pts == 0, axis=1)]

    hull = ConvexHull(mining_pts)
    hull_pts = mining_pts[hull.vertices]
    return hull_pts