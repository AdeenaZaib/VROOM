#!/usr/bin/env python3
"""
Single source of truth for the 5-zone TSN ring topology (OMNeT++ / INET).
Edit ZONES / RING_LINKS below, run `python3 gen_topology.py`, and it
re-validates the topology and regenerates ZonalRingTopology.ned + omnetpp.ini.
"""
import math, sys
from collections import deque

# ---------------------------------------------------------------- inventory
# (device name, link speed in Mbps, link length in metres [assumed, editable])
ZONES = {
    "FL": [("lidarFL", 1000, 1.5), ("radarFL", 100, 1.0), ("cameraFront", 1000, 2.0),
           ("cameraMirrorL", 1000, 1.5), ("steeringECU", 100, 1.5), ("brakeECU", 100, 1.5),
           ("ultrasonicFront", 100, 1.0), ("zcFL", 1000, 0.5)],
    "FR": [("lidarFR", 1000, 1.5), ("radarFR", 100, 1.0), ("cameraMirrorR", 1000, 1.5),
           ("powertrainECU", 100, 2.0), ("ultrasonicFR", 100, 1.0), ("headlampECU", 100, 1.0),
           ("zcFR", 1000, 0.5)],
    "RL": [("lidarRL", 1000, 1.5), ("radarRL", 100, 1.0), ("ultrasonicRL", 100, 1.0),
           ("zcRL", 1000, 0.5)],
    "RR": [("lidarRR", 1000, 1.5), ("radarRR", 100, 1.0), ("cameraRear", 1000, 1.5),
           ("v2xUnit", 100, 1.5), ("zcRR", 1000, 0.5)],
    "C":  [("infotainmentHU", 1000, 1.0), ("instrumentCluster", 100, 1.0),
           ("cameraDriverMonitor", 1000, 1.0), ("audioAmp", 100, 1.5),
           ("gnssReceiver", 100, 2.0), ("centralCompute", 1000, 1.0),
           ("connectivityGateway", 100, 1.5), ("zcC", 1000, 0.5)],
}
MASTER_CLOCK = ("masterClock", 100, 1.0, "C")      # gPTP grandmaster, attached to swC
NON_ECU = {"zcFL", "zcFR", "zcRL", "zcRR", "zcC", "centralCompute",
           "connectivityGateway", "masterClock"}   # not counted in the 25 endpoint ECUs

# switch <-> switch links: (a, b, speed Mbps, length m).  Ring + cabin dual-homing.
RING_LINKS = [("swFL", "swFR", 1000, 1.5), ("swFR", "swRR", 1000, 3.5),
              ("swRR", "swRL", 1000, 1.5), ("swRL", "swFL", 1000, 3.5),
              ("swC", "swFL", 1000, 2.0),  ("swC", "swFR", 1000, 2.0)]

SW_POS = {"swFL": (300, 300), "swFR": (800, 300), "swRL": (300, 900),
          "swRR": (800, 900), "swC": (550, 600)}
OUTWARD = {"FL": (-1, -1), "FR": (1, -1), "RL": (-1, 1), "RR": (1, 1), "C": None}

# ---------------------------------------------------------------- build graph
links = []            # (nodeA, nodeB, speed, length)
for a, b, s, l in RING_LINKS:
    links.append((a, b, s, l))
for z, devs in ZONES.items():
    for name, s, l in devs:
        links.append((f"sw{z}", name, s, l))
m, s, l, z = MASTER_CLOCK
links.append((f"sw{z}", m, s, l))

# per-node port numbering = order of connection creation (ethg++ order in NED)
port_of = {}          # (node, other) -> eth index
nports = {}
for a, b, _, _ in links:
    for n, o in ((a, b), (b, a)):
        port_of[(n, o)] = nports.get(n, 0)
        nports[n] = nports.get(n, 0) + 1

adj = {}
for a, b, _, _ in links:
    adj.setdefault(a, set()).add(b); adj.setdefault(b, set()).add(a)

# ---------------------------------------------------------------- validation
def reach(src, banned=None):
    seen, q = {src}, deque([src])
    while q:
        u = q.popleft()
        for v in adj[u]:
            if banned and {u, v} == set(banned): continue
            if v not in seen: seen.add(v); q.append(v)
    return seen

errors = []
all_nodes = set(adj)
if reach("swC") != all_nodes: errors.append("graph not connected")
# every non-switch node has exactly one port
for n in all_nodes:
    if not n.startswith("sw") and nports[n] != 1: errors.append(f"{n} has {nports[n]} ports")
# single-link-failure survivability of every switch-switch link
for a, b, _, _ in RING_LINKS:
    if reach("swC", banned=(a, b)) != all_nodes: errors.append(f"cutting {a}-{b} partitions the net")
# every zone switch has two edge-disjoint routes to swC (so FRER can use disjoint paths)
for sw in ("swFL", "swFR", "swRL", "swRR"):
    first = {v for v in adj[sw] if v.startswith("sw")}
    ok = False
    for a, b, _, _ in RING_LINKS:                       # remove each link, still reach swC
        pass
    # edge-disjoint check: max-flow of 2 via two removals -> simple: no single switch-link cut isolates sw
    for a, b, _, _ in RING_LINKS:
        if sw in reach("swC", banned=(a, b)): ok = True
        else: ok = False; break
    if not ok: errors.append(f"{sw} lacks redundancy to swC")
for a, b, s, l in links:
    if l >= 15: errors.append(f"link {a}-{b} is {l} m (>= 15 m)")
ecu_count = sum(1 for z in ZONES for n, _, _ in ZONES[z] if n not in NON_ECU)
if errors:
    print("VALIDATION FAILED:"); [print(" -", e) for e in errors]; sys.exit(1)

# ---------------------------------------------------------------- gPTP tree (static, rooted at masterClock)
parent, order = {"masterClock": None}, deque(["masterClock"])
# prefer the direct cabin uplinks, then the longitudinal ring links, so the tree is deterministic
while order:
    u = order.popleft()
    for v in sorted(adj[u]):
        if v not in parent: parent[v] = u; order.append(v)
children = {}
for v, p in parent.items():
    if p: children.setdefault(p, []).append(v)

# ---------------------------------------------------------------- positions
pos = dict(SW_POS)
pos["masterClock"] = (550, 450)
for z, devs in ZONES.items():
    sx, sy = SW_POS[f"sw{z}"]
    devs = [d for d in devs]
    n = len(devs)
    for i, (name, _, _) in enumerate(devs):
        if z == "C":
            ang = 2 * math.pi * i / n + math.pi / 2
        else:
            ox, oy = OUTWARD[z]; base = math.atan2(oy, ox)
            ang = base + (i - (n - 1) / 2) * (math.pi * 0.8 / max(n - 1, 1))
        r = 230 if z != "C" else 170
        pos[name] = (int(sx + r * math.cos(ang)), int(sy + r * math.sin(ang)))

# ---------------------------------------------------------------- emit NED
ned = []
ned.append("// Generated by gen_topology.py - edit the script, not this file.\n"
           "// 5-zone TSN zonal ring (4 corner zones + cabin/centre zone).\n"
           "// Requires OMNeT++ 6.x and INET 4.5+/master (TsnClock, TsnSwitch, TsnDevice).\n"
           "import inet.networks.base.TsnNetworkBase;\n"
           "import inet.node.ethernet.EthernetLink;\n"
           "import inet.node.tsn.TsnClock;\n"
           "import inet.node.tsn.TsnDevice;\n"
           "import inet.node.tsn.TsnSwitch;\n\n"
           "network ZonalRingTopology extends TsnNetworkBase\n{\n"
           '    @display("bgb=1100,1150");\n    submodules:')
for sw, (x, y) in SW_POS.items():
    ned.append(f'        {sw}: TsnSwitch {{ @display("p={x},{y}"); }}')
ned.append(f'        {MASTER_CLOCK[0]}: TsnClock {{ @display("p={pos["masterClock"][0]},{pos["masterClock"][1]}"); }}')
for z, devs in ZONES.items():
    ned.append(f"        // ---- zone {z}")
    for name, _, _ in devs:
        x, y = pos[name]
        ned.append(f'        {name}: TsnDevice {{ @display("p={x},{y}"); }}')
ned.append("    connections:")
ned.append("        // ---- ring + cabin dual-homing (1 Gbps)")
for a, b, _, l in links[:len(RING_LINKS)]:
    ned.append(f"        {a}.ethg++ <--> EthernetLink {{ length = {l}m; }} <--> {b}.ethg++;")
for z, devs in ZONES.items():
    ned.append(f"        // ---- zone {z} access links")
    for name, _, l in devs:
        ned.append(f"        sw{z}.ethg++ <--> EthernetLink {{ length = {l}m; }} <--> {name}.ethg++;")
ned.append("        // ---- gPTP grandmaster")
ned.append(f"        sw{MASTER_CLOCK[3]}.ethg++ <--> EthernetLink {{ length = {MASTER_CLOCK[2]}m; }} <--> {MASTER_CLOCK[0]}.ethg++;")
ned.append("}\n")
open("ZonalRingTopology.ned", "w").write("\n".join(ned))

# ---------------------------------------------------------------- emit INI
ini = []
ini.append("""# Generated by gen_topology.py - edit the script, not this file.
[General]
network = ZonalRingTopology
sim-time-limit = 2s
simtime-resolution = fs
description = "5-zone TSN zonal ring: topology + gPTP only (no application traffic yet)"

**.transmitter.typename = "StreamingTransmitter"
**.receiver.typename = "DestreamingReceiver"

# gPTP / local clocks in every node (same pattern as the INET gPTP showcase)
*.*.hasTimeSynchronization = true
**.masterClock.clock.oscillator.typename = "RandomDriftOscillator"
**.oscillator.nominalTickLength = 10ns
**.oscillator.changeInterval = 12.5ms
**.oscillator.driftRate = uniform(-100ppm, 100ppm)
**.oscillator.driftRateChange = uniform(-1ppm, 1ppm)
**.oscillator.driftRateChangeUpperLimit = 100ppm
**.oscillator.driftRateChangeLowerLimit = -100ppm
**.referenceClock = "masterClock.clock"

# visualisation (optional, GUI only)
*.visualizer.typename = "IntegratedMultiCanvasVisualizer"
*.visualizer.dataLinkVisualizer[0].displayLinks = true
*.visualizer.dataLinkVisualizer[0].activityLevel = "protocol"
*.visualizer.dataLinkVisualizer[0].packetFilter = "GptpSync"
*.visualizer.dataLinkVisualizer[0].lineColor = "blue2"
""")
ini.append("# ---- per-interface bit rates (derived from the link table)")
rate = {}
for a, b, s, _ in links:
    rate[(a, port_of[(a, b)])] = s; rate[(b, port_of[(b, a)])] = s
for (n, p), s in sorted(rate.items()):
    val = "1Gbps" if s == 1000 else f"{s}Mbps"
    ini.append(f"*.{n}.eth[{p}].bitrate = {val}")
ini.append("\n# ---- static gPTP tree rooted at masterClock -> swC -> {swFL, swFR} -> {swRL, swRR} -> devices")
ini.append("# (ring links FL-FR and RL-RR stay unused for sync; INET gPTP has no BMCA, ports are static)")
ini.append(f'*.masterClock.gptp.masterPorts = ["eth{port_of[("masterClock","swC")]}"]')
for n in sorted(adj):
    if not n.startswith("sw"): continue
    p = parent[n]
    ini.append(f'*.{n}.gptp.slavePort = "eth{port_of[(n, p)]}"')
    ch = ", ".join(f'"eth{port_of[(n, c)]}"' for c in children.get(n, []))
    ini.append(f"*.{n}.gptp.masterPorts = [{ch}]")
open("omnetpp.ini", "w").write("\n".join(ini) + "\n")

print(f"OK  switches=5  endpoint ECUs (excl. zone controllers/central nodes)={ecu_count}  "
      f"nodes={len(all_nodes)}  links={len(links)}")
for sw in sorted(k for k in nports if k.startswith('sw')):
    print(f"  {sw}: {nports[sw]} ports")
print("  gPTP children:", {k: v for k, v in children.items() if k.startswith('sw') or k == 'masterClock'})
