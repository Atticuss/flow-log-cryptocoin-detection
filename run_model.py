import preprocess
import numpy as np
import matplotlib.pyplot as plt

from scipy.spatial import ConvexHull, Delaunay

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

# https://stackoverflow.com/a/16898636
def get_hull_membership_rate(target_pts, hull_pts):
    """
    Test if points in `p` are in `hull`

    `p` should be a `NxK` coordinates of `N` points in `K` dimensions
    `hull` is either a scipy.spatial.Delaunay object or the `MxK` array of the 
    coordinates of `M` points in `K`dimensions for which Delaunay triangulation
    will be computed
    """
    del_tesselation = Delaunay(hull_pts)
    member_mask = del_tessellation.find_simplex(target_pts) >= 0
    return target_pts[member_mask].size / target_pts.size


def convex_hull_test(hull_model_pts, min_membership_rate):
    ret_data = preprocess.load_and_build_enis()
    boundary_matches = {}
    total = 0

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

    for eni_idx, (eni, v) in enumerate(ret_data.items()):
        if eni in mining_enis:
            continue

        for traffic_id, data in v.items():
            total += 1
            src_bytes_all, src_pkts_all, dst_bytes_all, dst_pkts_all, src_ports, dst_ports, src_port_switch_event_intervals, dst_port_switch_event_intervals, src_port_switch_pkt_intervals, dst_port_switch_pkt_invervals = (
                data
            )

        target_pts = np.column_stack(
            (src_bytes_all, src_pkts_all, dst_bytes_all, dst_pkts_all)
        )

        # strip out [0,0,0,0] cols
        target_pts = target_pts[~np.all(target_pts == 0, axis=1)]
        if len(target_pts) == 0:
            continue

        membership_rate = get_hull_membership_rate(target_pts, hull_pts)
        if membership_rate >= min_membership_rate:
            if eni not in boundary_matches.keys():
                boundary_matches[eni] = []
            boundary_matches[eni].append(traffic_id)

    return boundary_matches
