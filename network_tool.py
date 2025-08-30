import argparse
import ipaddress
import os
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from queue import Queue
from typing import Dict, List, Tuple, Optional

import matplotlib.pyplot as plt
import networkx as nx

# -------------------------
# Utility & Data Structures
# -------------------------

@dataclass
class Interface:
    name: str
    ip: Optional[str] = None
    mask: Optional[str] = None
    mtu: Optional[int] = None
    bandwidth_kbps: Optional[int] = None
    description: Optional[str] = None
    vlan: Optional[int] = None  # for subinterfaces encapsulation dot1Q
    is_subif: bool = False

@dataclass
class Device:
    name: str
    dtype: str  # 'router' | 'switch' | 'host'
    interfaces: Dict[str, Interface] = field(default_factory=dict)

@dataclass
class Link:
    a: str
    b: str
    bandwidth_mbps: float = 100.0
    mtu: Optional[int] = None
    label: Optional[str] = None

# -------------------------
# Parsing
# -------------------------

HOSTNAME_RE = re.compile(r"^hostname\s+(\S+)", re.MULTILINE)
# Capture interface blocks including subinterfaces like GigabitEthernet0/0.10
INTF_BLOCK_RE = re.compile(r"^interface\s+([A-Za-z]+[A-Za-z0-9/\.]+)\s*\n(.*?)(?=^\S|\Z)", re.MULTILINE | re.DOTALL)
IP_RE = re.compile(r"ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)")
BW_RE = re.compile(r"bandwidth\s+(\d+)")  # in kbps on Cisco
MTU_RE = re.compile(r"mtu\s+(\d+)")
DESC_RE = re.compile(r"description\s+(.+)")
ENCAP_DOT1Q_RE = re.compile(r"encapsulation\s+dot1Q\s+(\d+)")

def parse_router_config(text: str) -> Device:
    hostname = HOSTNAME_RE.search(text)
    name = hostname.group(1) if hostname else "UNKNOWN"
    dev = Device(name=name, dtype="router", interfaces={})

    for m in INTF_BLOCK_RE.finditer(text):
        iname = m.group(1).strip()
        body = m.group(2)
        iface = Interface(name=iname)

        ipm = IP_RE.search(body)
        if ipm:
            iface.ip, iface.mask = ipm.group(1), ipm.group(2)

        bwm = BW_RE.search(body)
        if bwm:
            iface.bandwidth_kbps = int(bwm.group(1))

        mtum = MTU_RE.search(body)
        if mtum:
            iface.mtu = int(mtum.group(1))

        descm = DESC_RE.search(body)
        if descm:
            iface.description = descm.group(1).strip()

        encm = ENCAP_DOT1Q_RE.search(body)
        if encm:
            iface.vlan = int(encm.group(1))
            iface.is_subif = True

        # Defaults if bandwidth not set
        if iface.bandwidth_kbps is None:
            if iname.lower().startswith("gigabitethernet"):
                iface.bandwidth_kbps = 100000  # 100 Mbps default if unset
            elif iname.lower().startswith("fastethernet"):
                iface.bandwidth_kbps = 10000   # 10 Mbps
            elif iname.lower().startswith("serial"):
                iface.bandwidth_kbps = 1544    # ~T1
            else:
                iface.bandwidth_kbps = 100000

        dev.interfaces[iname] = iface
    return dev

def load_devices(config_dir="configs", switch_dir="switches") -> Dict[str, Device]:
    devices: Dict[str, Device] = {}
    if os.path.isdir(config_dir):
        for f in os.listdir(config_dir):
            if f.lower().endswith(".txt"):
                with open(os.path.join(config_dir, f), "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
                d = parse_router_config(text)
                devices[d.name] = d
    # Switch configs (optional) - very light parsing for hostname only
    if os.path.isdir(switch_dir):
        for f in os.listdir(switch_dir):
            if f.lower().endswith(".txt"):
                with open(os.path.join(switch_dir, f), "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
                hostname = HOSTNAME_RE.search(text)
                name = hostname.group(1) if hostname else f.replace(".txt", "")
                devices[name] = Device(name=name, dtype="switch", interfaces={})
    return devices

# -------------------------
# Topology Inference
# -------------------------

def ip_to_network(ip: str, mask: str) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(f"{ip}/{mask}", strict=False)

def build_graph(devices: Dict[str, Device], links_csv: Optional[str] = "links.csv") -> Tuple[nx.Graph, List[Link]]:
    G = nx.Graph()
    for name, dev in devices.items():
        G.add_node(name, dtype=dev.dtype)

    # If user provides links.csv, trust it. Else, infer LAN groupings by identical subnets.
    links: List[Link] = []
    if links_csv and os.path.exists(links_csv):
        import csv
        with open(links_csv, newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                links.append(Link(
                    a=row["endpointA"].strip(),
                    b=row["endpointB"].strip(),
                    bandwidth_mbps=float(row.get("bandwidth_mbps", 100)),
                    mtu=int(row["mtu"]) if row.get("mtu") else None,
                    label=row.get("label") or None
                ))
    else:
        # Infer links: if two interfaces across devices share the same /30 network,
        # assume it's a point-to-point link. For LAN /24, create a pseudo switch node if absent.
        subnet_map = defaultdict(list)  # network -> [(device, interface)]
        for d in devices.values():
            for iface in d.interfaces.values():
                if iface.ip and iface.mask:
                    try:
                        net = ip_to_network(iface.ip, iface.mask)
                        subnet_map[str(net)].append((d.name, iface))
                    except Exception:
                        pass
        # For each subnet: if exactly 2 router interfaces -> link them. If >2, assume LAN/switch.
        for net, members in subnet_map.items():
            if len(members) == 2:
                (d1, i1), (d2, i2) = members
                bw_mbps = min(i1.bandwidth_kbps, i2.bandwidth_kbps) / 1000.0
                mtu = None
                if i1.mtu and i2.mtu:
                    mtu = min(i1.mtu, i2.mtu)
                links.append(Link(a=d1, b=d2, bandwidth_mbps=bw_mbps, mtu=mtu, label=f"ptp {net}"))
            elif len(members) > 2:
                # create or reuse a pseudo switch node for the LAN/VLAN
                sw_node = f"SW_{net}"
                if sw_node not in devices:
                    G.add_node(sw_node, dtype="switch")
                for (dname, iface) in members:
                    bw_mbps = iface.bandwidth_kbps / 1000.0
                    links.append(Link(a=dname, b=sw_node, bandwidth_mbps=bw_mbps, mtu=iface.mtu, label=f"lan {net}"))

    # Add edges
    for lk in links:
        G.add_edge(lk.a, lk.b, bandwidth_mbps=lk.bandwidth_mbps, mtu=lk.mtu, label=lk.label)
    return G, links

# -------------------------
# Validations
# -------------------------

def validate(devices: Dict[str, Device], G: nx.Graph, links: List[Link], endpoints_csv: Optional[str] = "endpoints.csv") -> str:
    report = []
    report.append("=== VALIDATION REPORT ===")

    # Duplicate IPs & overlapping subnets
    ip_map = {}
    dup_ips = []
    subnets = []
    for d in devices.values():
        for iface in d.interfaces.values():
            if iface.ip and iface.mask:
                key = iface.ip
                if key in ip_map:
                    dup_ips.append((key, ip_map[key], (d.name, iface.name)))
                else:
                    ip_map[key] = (d.name, iface.name)
                try:
                    subnets.append((d.name, iface.name, ip_to_network(iface.ip, iface.mask)))
                except Exception:
                    pass
    if dup_ips:
        report.append("⚠ Duplicate IP addresses found:")
        for ip, a, b in dup_ips:
            report.append(f"  - {ip} used by {a} and {b}")
    else:
        report.append("✅ No duplicate IPs detected.")

    # Overlapping subnets (basic pairwise check)
    overlaps = []
    for i in range(len(subnets)):
        for j in range(i+1, len(subnets)):
            n1 = subnets[i][2]
            n2 = subnets[j][2]
            if n1.overlaps(n2) and n1 != n2:
                overlaps.append((subnets[i][:2], subnets[j][:2], str(n1), str(n2)))
    if overlaps:
        report.append("⚠ Overlapping subnets detected:")
        for a, b, n1, n2 in overlaps:
            report.append(f"  - {a}({n1}) overlaps {b}({n2})")
    else:
        report.append("✅ No overlapping subnets detected.")

    # Heuristic: Non-standard gateway (router LAN IP not .1)
    for d in devices.values():
        for iface in d.interfaces.values():
            if iface.ip and iface.mask:
                net = ip_to_network(iface.ip, iface.mask)
                host_part = int(str(iface.ip).split(".")[-1])
                if net.prefixlen >= 24:  # simple heuristic for /24 or smaller
                    if host_part != 1:
                        report.append(f"ℹ Gateway heuristic: {d.name} {iface.name} has IP {iface.ip} on {net}. Not .1 — check default gateway settings on hosts.")

    # Subinterface/VLAN labeling vs encapsulation
    for d in devices.values():
        for iface in d.interfaces.values():
            if iface.is_subif and iface.vlan:
                if not (iface.description and str(iface.vlan) in iface.description):
                    report.append(f"⚠ {d.name} {iface.name}: encapsulation dot1Q {iface.vlan} but description doesn't mention VLAN {iface.vlan}. Consider labeling correctly.")
            if iface.is_subif and iface.ip and not iface.vlan:
                report.append(f"⚠ {d.name} {iface.name}: subinterface has IP but no 'encapsulation dot1Q' detected.")

    # Potential loops (graph cycles)
    if not nx.is_tree(G):
        cycles = list(nx.cycle_basis(G))
        if cycles:
            report.append("⚠ Potential loops (cycles) detected in topology:")
            for cyc in cycles[:5]:
                report.append(f"  - Cycle: {' -> '.join(cyc)}")
        else:
            report.append("ℹ Graph is not a tree, but no simple cycles found.")
    else:
        report.append("✅ No cycles; topology is a tree.")

    # Missing switch configs (inferred L2)
    for n, attrs in G.nodes(data=True):
        if attrs.get("dtype") == "switch":
            if n.startswith("SW_"):
                report.append(f"⚠ Missing switch configuration for inferred L2 node: {n}. Provide switch config in switches/ to validate VLANs, STP, etc.")

    # Optional PC endpoint sanity checks
    if endpoints_csv and os.path.exists(endpoints_csv):
        import csv
        with open(endpoints_csv, newline="") as fh:
            rdr = csv.DictReader(fh)
            for row in rdr:
                ip = row.get("host_ip")
                gw = row.get("gateway_ip")
                if ip and gw:
                    try:
                        # Assume /24 for quick validation unless subnet column provided
                        subnet = row.get("subnet") or f"{ip}/24"
                        net = ipaddress.ip_network(subnet, strict=False)
                        if ipaddress.ip_address(gw) not in net:
                            report.append(f"⚠ Endpoint {row.get('host_name')} gateway {gw} not in same subnet as {ip}.")
                    except Exception:
                        pass

    return "\n".join(report)

# -------------------------
# Load & Capacity Analysis
# -------------------------

def load_analysis(G: nx.Graph, links: List[Link], traffic_csv: Optional[str] = "traffic_demands.csv") -> str:
    report = []
    report.append("=== LOAD ANALYSIS ===")
    if not (traffic_csv and os.path.exists(traffic_csv)):
        report.append("ℹ No traffic_demands.csv provided. Skipping load computation.")
        return "\n".join(report)

    import csv

    def resolve_subnet_node(subnet_str: str) -> Optional[str]:
        if subnet_str in G.nodes:
            return subnet_str
        sw_guess = f"SW_{subnet_str}"
        if sw_guess in G.nodes:
            return sw_guess
        return None

    # Precompute edge capacities dict
    edge_capacity = {}
    for (u, v, data) in G.edges(data=True):
        cap = data.get("bandwidth_mbps", 100.0)
        edge_capacity[(u, v)] = cap
        edge_capacity[(v, u)] = cap

    # Aggregate loads per edge
    edge_load = defaultdict(float)

    rows = []
    with open(traffic_csv, newline="") as fh:
        rdr = csv.DictReader(fh)
        for row in rdr:
            rows.append(row)

    for row in rows:
        src = resolve_subnet_node(row["src_subnet"].strip())
        dst = resolve_subnet_node(row["dst_subnet"].strip())
        mbps = float(row.get("mbps", 0))
        if src is None or dst is None or not G.has_node(src) or not G.has_node(dst):
            report.append(f"ℹ Skipping demand {row} (unresolved nodes). Provide SW_{row['src_subnet']} or links.csv with your switch names.")
            continue

        try:
            path = nx.shortest_path(G, src, dst, weight=None)
        except nx.NetworkXNoPath:
            report.append(f"⚠ No path between {src} and {dst}.")
            continue

        for i in range(len(path)-1):
            u, v = path[i], path[i+1]
            edge_load[(u, v)] += mbps
            edge_load[(v, u)] += mbps

    overloads = []
    for (u, v), load in edge_load.items():
        cap = edge_capacity.get((u, v), 100.0)
        if load > cap:
            overloads.append((u, v, load, cap))

    if not overloads:
        report.append("✅ No overloaded links for provided demands.")
    else:
        report.append("⚠ Overloaded links:")
        for u, v, load, cap in overloads:
            report.append(f"  - {u} <-> {v}: load {load:.2f} Mbps > capacity {cap:.2f} Mbps")
            # Try alternate path suggestion
            G2 = G.copy()
            if G2.has_edge(u, v):
                G2.remove_edge(u, v)
                try:
                    alt_path = nx.shortest_path(G2, u, v)
                    report.append(f"    Suggestion: reroute via: {' -> '.join(alt_path)}")
                except nx.NetworkXNoPath:
                    report.append("    No alternate path; consider capacity upgrade or redundancy.")

    # Simple protocol recommendation
    try:
        diam = nx.diameter(G)
    except Exception:
        diam = 0
    if diam >= 4:
        report.append("ℹ Topology diameter is high; consider BGP for inter-domain scaling; OSPF is fine intra-domain.")
    else:
        report.append("ℹ OSPF appears adequate; consider BGP if connecting to external AS or policy-heavy paths.")

    return "\n".join(report)

# -------------------------
# Drawing
# -------------------------

def draw_topology(G: nx.Graph, out_png="output/network_topology.png"):
    os.makedirs(os.path.dirname(out_png), exist_ok=True)
    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G, seed=7)
    node_colors = []
    for n, attrs in G.nodes(data=True):
        if attrs.get("dtype") == "router":
            node_colors.append("lightblue")
        elif attrs.get("dtype") == "switch":
            node_colors.append("lightgreen")
        else:
            node_colors.append("lightgray")
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=1200)
    nx.draw_networkx_edges(G, pos)
    labels = {n: n for n in G.nodes()}
    nx.draw_networkx_labels(G, pos, labels=labels, font_size=9)
    edge_labels = {(u, v): f"{data.get('bandwidth_mbps','?')}Mbps" for (u, v, data) in G.edges(data=True)}
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8)
    plt.title("Network Topology")
    plt.axis('off')
    plt.savefig(out_png, bbox_inches="tight")
    plt.close()

# -------------------------
# Simulation
# -------------------------

class SimNode(threading.Thread):
    def __init__(self, name: str, dtype: str, inbox: Queue, neighbors: List[str], pause_evt: threading.Event, stop_evt: threading.Event, log_fn):
        super().__init__(daemon=True)
        self.name = name
        self.dtype = dtype
        self.inbox = inbox
        self.neighbors = neighbors
        self.pause_evt = pause_evt
        self.stop_evt = stop_evt
        self.log = log_fn
        self.hello_seen = set()

    def run(self):
        self.log(f"[{self.name}] starting ({self.dtype})")
        while not self.stop_evt.is_set():
            self.pause_evt.wait()
            # Periodic hello
            for nb in self.neighbors:
                send(("HELLO", self.name, nb))
            try:
                msg = self.inbox.get(timeout=0.1)
                self.handle_msg(msg)
            except Exception:
                pass
            time.sleep(0.2)
        self.log(f"[{self.name}] stopping")

    def handle_msg(self, msg):
        mtype, src, dst = msg[:3]
        if dst != self.name and dst != "BCAST":
            return
        if mtype == "HELLO":
            self.hello_seen.add(src)
            self.log(f"[{self.name}] HELLO from {src}")
        elif mtype == "ARP_REQ":
            if self.dtype in ("router", "switch"):
                send(("ARP_REP", self.name, src))
                self.log(f"[{self.name}] ARP reply to {src}")
        elif mtype == "FAIL_LINK":
            pass

BUS = Queue()
NODE_INBOX: Dict[str, Queue] = {}

def send(message):
    BUS.put(message)

def sim_topology(G: nx.Graph, duration=5.0, out_log="output/sim_log.txt", pause_resume: bool = False):
    os.makedirs(os.path.dirname(out_log), exist_ok=True)
    logs = deque(maxlen=10000)
    def log_fn(s):
        logs.append(s)

    pause_evt = threading.Event()
    stop_evt = threading.Event()
    pause_evt.set()

    nodes = {}
    for n in G.nodes():
        NODE_INBOX[n] = Queue()
    for n in G.nodes():
        neighbors = list(G.neighbors(n))
        dtype = G.nodes[n].get("dtype", "unknown")
        t = SimNode(n, dtype, NODE_INBOX[n], neighbors, pause_evt, stop_evt, log_fn)
        nodes[n] = t

    for t in nodes.values():
        t.start()

    for n in G.nodes():
        if n.lower().startswith(("pc", "host")):
            send(("ARP_REQ", n, "BCAST"))

    start = time.time()
    paused_once = False
    while time.time() - start < duration:
        try:
            m = BUS.get(timeout=0.1)
            mtype, src, dst = m[:3]
            if dst == "BCAST":
                for nb in list(G.neighbors(src)):
                    NODE_INBOX[nb].put((mtype, src, nb))
            else:
                if dst in G.neighbors(src):
                    NODE_INBOX[dst].put(m)
        except Exception:
            pass
        if pause_resume and not paused_once and time.time() - start > duration/2:
            log_fn("[SIM] Pausing...")
            pause_evt.clear()
            time.sleep(0.8)
            log_fn("[SIM] Resuming...")
            pause_evt.set()
            paused_once = True

    stop_evt.set()
    time.sleep(0.5)
    with open(out_log, "w", encoding="utf-8") as fh:
        fh.write("\n".join(logs))

# -------------------------
# CLI
# -------------------------

def main():
    ap = argparse.ArgumentParser(description="Cisco VIP 2025 Network Tool")
    ap.add_argument("--configs", default="configs", help="Router configs folder")
    ap.add_argument("--switches", default="switches", help="Switch configs folder (optional)")
    ap.add_argument("--links", default="links.csv", help="links.csv (optional)")
    ap.add_argument("--endpoints", default="endpoints.csv", help="endpoints.csv (optional)")
    ap.add_argument("--traffic", default="traffic_demands.csv", help="traffic_demands.csv (optional)")
    ap.add_argument("--draw", action="store_true", help="Draw topology PNG")
    ap.add_argument("--analyze", action="store_true", help="Run validations and load analysis")
    ap.add_argument("--simulate", action="store_true", help="Run Day-1 simulation")
    ap.add_argument("--sim-seconds", type=float, default=6.0, help="Simulation duration seconds")
    args = ap.parse_args()

    devices = load_devices(args.configs, args.switches)
    if not devices:
        print("No devices parsed. Put router configs in ./configs/*.txt")
        return
    G, links = build_graph(devices, args.links)

    if args.draw:
        draw_topology(G)

    if args.analyze:
        vr = validate(devices, G, links, args.endpoints)
        os.makedirs("output", exist_ok=True)
        with open("output/validation_report.txt", "w", encoding="utf-8") as fh:
            fh.write(vr)
        la = load_analysis(G, links, args.traffic)
        with open("output/load_analysis.txt", "w", encoding="utf-8") as fh:
            fh.write(la)
        print("Validation and load analysis written to output/*.txt")

    if args.simulate:
        sim_topology(G, duration=args.sim_seconds, pause_resume=True)

    if args.draw:
        print("Topology image saved to output/network_topology.png")

if __name__ == "__main__":
    main()
