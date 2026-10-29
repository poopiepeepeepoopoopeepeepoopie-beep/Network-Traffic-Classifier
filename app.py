"""
Network Traffic Classifier and Usage Dashboard  (single-file app)

Run:   python -m streamlit run app.py

Three ways to get data, all chosen from the sidebar:
  1. Upload a capture file (.pcap / .pcapng / .cap)
  2. Pick a capture from the Datasets/ folder next to this file
  3. Capture live from a network interface (needs Npcap on Windows and an
     Administrator terminal on Windows / sudo on Linux and macOS)

Only capture on networks you are authorised to monitor.
"""
import ipaddress
import os
import tempfile
import threading
import time
from collections import deque
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st
from scapy.all import (AsyncSniffer, PcapReader, PcapWriter, conf,
                       ARP, IP, IPv6, TCP, UDP, ICMP, DNS)

st.set_page_config(page_title="Network Traffic Dashboard", layout="wide")

BASE = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE, "Datasets")
os.makedirs(DATASET_DIR, exist_ok=True)
CAPTURE_EXT = (".pcap", ".pcapng", ".cap")
LOCAL_TZ = datetime.now().astimezone().tzinfo
MAX_LIVE_ROWS = 200_000

COLUMNS = ["Timestamp", "Source IP", "Destination IP", "Source Port",
           "Destination Port", "Protocol", "Service", "Size"]

PORT_SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    161: "SNMP", 443: "HTTPS", 445: "SMB", 587: "SMTP", 631: "IPP (printing)",
    993: "IMAPS", 3306: "MySQL", 3389: "RDP", 5060: "SIP", 8080: "HTTP-alt",
}
ALL_PROTOCOLS = ["TCP", "UDP", "DNS", "ICMP", "ICMPv6", "ARP", "Other"]
ALL_SERVICES = sorted(set(PORT_SERVICES.values()) |
                      {"ARP", "ICMP", "ICMPv6", "Other / ephemeral", "Other"})
# adapters that rarely carry your real traffic: listed after the useful ones
VIRTUAL_HINTS = ("bluetooth", "virtual", "vmware", "vbox", "hyper-v", "vethernet", "loopback",
                 "wan miniport", "tap-", "tunnel", "pseudo", "docker", "wsl", "teredo", "isatap")


# ======================================================================
# Packet parsing and classification (same logic as main.py)
# ======================================================================
def norm_ip(ip):
    try:
        return ipaddress.ip_address(str(ip).split("%")[0]).compressed
    except ValueError:
        return str(ip)


def classify_service(protocol, sport, dport):
    if protocol in ("ARP", "ICMP", "ICMPv6"):
        return protocol
    for port in (dport, sport):
        if port is not None and int(port) in PORT_SERVICES:
            return PORT_SERVICES[int(port)]
    return "Other / ephemeral" if sport is not None else "Other"


def extract(packet):
    src = dst = "Unknown"
    sport = dport = None
    proto = "Other"

    if IP in packet:
        src, dst = packet[IP].src, packet[IP].dst
    elif IPv6 in packet:
        src, dst = packet[IPv6].src, packet[IPv6].dst
    elif ARP in packet:
        src, dst = packet[ARP].psrc, packet[ARP].pdst

    if TCP in packet:
        sport, dport, proto = packet[TCP].sport, packet[TCP].dport, "TCP"
    elif UDP in packet:
        sport, dport, proto = packet[UDP].sport, packet[UDP].dport, "UDP"
    elif ICMP in packet:
        proto = "ICMP"
    elif IPv6 in packet and packet[IPv6].nh == 58:
        proto = "ICMPv6"
    elif ARP in packet:
        proto = "ARP"
    if DNS in packet:
        proto = "DNS"

    return [float(packet.time), src, dst, sport, dport, proto,
            classify_service(proto, sport, dport), len(packet)]


def dns_answers(packet):
    """(ip, domain) pairs from a DNS response, so charts can show names instead of bare IPs."""
    if DNS not in packet:
        return []
    dns = packet[DNS]
    if dns.qr != 1 or not dns.ancount or not dns.qd:
        return []
    try:
        q = dns.qd[0] if isinstance(dns.qd, list) else dns.qd
        name = q.qname.decode(errors="ignore").rstrip(".")
        out, rr = [], dns.an
        for _ in range(dns.ancount):
            if rr is None or not hasattr(rr, "rdata"):
                break
            if rr.type in (1, 28) and isinstance(rr.rdata, str):   # A / AAAA records
                out.append((norm_ip(rr.rdata), name))
            rr = rr.payload
        return out
    except Exception:
        return []


def to_frame(rows):
    df = pd.DataFrame(rows, columns=COLUMNS)
    for c in ("Source Port", "Destination Port"):
        df[c] = pd.to_numeric(df[c], errors="coerce").astype("Int64")
    df["Time"] = (pd.to_datetime(df["Timestamp"].astype(float), unit="s", utc=True)
                  .dt.tz_convert(LOCAL_TZ).dt.tz_localize(None))
    return df


def parse_pcap(path, max_packets):
    rows, names, truncated = [], {}, False
    with PcapReader(path) as reader:
        for i, pkt in enumerate(reader):
            if i >= max_packets:
                truncated = True
                break
            rows.append(extract(pkt))
            for ip, name in dns_answers(pkt):
                names[ip] = name
    return to_frame(rows), truncated, names


@st.cache_data(show_spinner="Parsing capture file...")
def parse_path(path, mtime, max_packets):
    return parse_pcap(path, max_packets)


@st.cache_data(show_spinner="Parsing uploaded file...")
def parse_upload(name, data, max_packets):
    suffix = os.path.splitext(name)[1] or ".pcap"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as f:
        f.write(data)
        tmp = f.name
    try:
        return parse_pcap(tmp, max_packets)
    finally:
        os.remove(tmp)


# ======================================================================
# Live capture (background thread that survives Streamlit reruns)
# ======================================================================
class LiveSession:
    def __init__(self):
        self.lock = threading.Lock()
        self.rows = deque(maxlen=MAX_LIVE_ROWS)
        self.names = {}
        self.total = 0
        self.errors = 0
        self.sniffer = None
        self.writer = None
        self.saved_path = None
        self.iface = None
        self.local_ips = frozenset()
        self.started_at = None
        self.error = None

    @property
    def running(self):
        sn = self.sniffer
        return sn is not None and sn.thread is not None and sn.thread.is_alive()

    def _handle(self, pkt):
        try:
            row = extract(pkt)
            answers = dns_answers(pkt)
            with self.lock:
                self.rows.append(row)
                self.total += 1
                for ip, name in answers:
                    self.names[ip] = name
            if self.writer is not None:
                self.writer.write(pkt)
        except Exception:
            self.errors += 1                     # one odd packet must not kill the capture

    def start(self, iface, bpf, local_ips, save_raw):
        self.stop()
        self.clear()
        self.error, self.saved_path = None, None
        try:
            if save_raw:
                self.saved_path = os.path.join(DATASET_DIR, f"live_{datetime.now():%Y%m%d_%H%M%S}.pcap")
                self.writer = PcapWriter(self.saved_path, sync=True)
            sn = AsyncSniffer(iface=iface or None, prn=self._handle,
                              store=False, filter=bpf or None)
            sn.start()
            time.sleep(0.6)                      # give it a moment to fail loudly
            if sn.exception is not None:
                raise sn.exception
            if sn.thread is None or not sn.thread.is_alive():
                raise RuntimeError("Capture stopped immediately.")
        except Exception as e:                   # permission, missing Npcap, bad filter...
            self.error = f"{type(e).__name__}: {e}"
            self.sniffer = None
            self._close_writer(remove_if_empty=True)
            return
        self.sniffer, self.iface, self.started_at = sn, iface, datetime.now()
        self.local_ips = frozenset(norm_ip(i) for i in local_ips)

    def _close_writer(self, remove_if_empty=False):
        if self.writer is not None:
            try:
                self.writer.close()
            except Exception:
                pass
            self.writer = None
            if remove_if_empty and self.saved_path and os.path.exists(self.saved_path) \
                    and os.path.getsize(self.saved_path) <= 24:
                os.remove(self.saved_path)
                self.saved_path = None

    def stop(self):
        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception:
                pass
        self._close_writer()

    def clear(self):
        with self.lock:
            self.rows.clear()
            self.names = {}
            self.total = 0
            self.errors = 0

    def snapshot(self):
        with self.lock:
            return to_frame(list(self.rows)), dict(self.names)


@st.cache_resource
def get_session():
    return LiveSession()


def iface_ips(i):
    ips = set()
    try:
        for lst in (getattr(i, "ips", None) or {}).values():
            ips.update(lst)
    except Exception:
        pass
    if getattr(i, "ip", None):
        ips.add(i.ip)
    return tuple(sorted(norm_ip(x) for x in ips if x))


@st.cache_data(ttl=60)
def list_interfaces():
    """[(label, scapy_name, ips)] with the interface that has the default route first."""
    default = getattr(conf.iface, "name", str(conf.iface))
    items = []
    for i in conf.ifaces.values():
        name = getattr(i, "name", str(i))
        ip = getattr(i, "ip", "") or ""
        text = f"{name} {getattr(i, 'description', '')}".lower()
        no_net = ip.startswith("169.254.") or not ip
        loop = ip.startswith("127.") or "loopback" in text
        virtual = any(h in text for h in VIRTUAL_HINTS)
        if name == default:
            rank, tag = 0, "  ★ default route"
        elif not no_net and not loop and not virtual:
            rank, tag = 1, ""
        elif not loop and not no_net:
            rank, tag = 2, "  (virtual)"
        else:
            rank, tag = 3, "  (no network)" if no_net and not loop else "  (loopback)"
        label = (f"{name}  [{ip}]" if ip else name) + tag
        items.append((rank, label, name, iface_ips(i)))
    items.sort(key=lambda t: (t[0], t[1]))
    return [(label, name, ips) for _, label, name, ips in items]


# ======================================================================
# Analysis + charts
# ======================================================================
def chart(fig, key):
    try:
        st.plotly_chart(fig, width="stretch", key=key)
    except TypeError:
        st.plotly_chart(fig, use_container_width=True, key=key)


def table(df):
    try:
        st.dataframe(df, width="stretch", hide_index=True)
    except Exception:
        st.dataframe(df, use_container_width=True, hide_index=True)


def apply_filters(df, protos, services, ip):
    df = df[df["Protocol"].isin(protos) & df["Service"].isin(services)]
    if ip:
        df = df[(df["Source IP"] == ip) | (df["Destination IP"] == ip)]
    return df


def add_direction(df, local):
    """Upload = sent by this machine, Download = received by it (live mode)."""
    src_local = df["Source IP"].map(norm_ip).isin(local)
    dst_local = df["Destination IP"].map(norm_ip).isin(local)
    df = df.copy()
    df["Direction"] = "Other"
    df.loc[dst_local & ~src_local, "Direction"] = "Download"
    df.loc[src_local & ~dst_local, "Direction"] = "Upload"
    return df


def host_traffic(df, local):
    """Bytes per host. With local IPs known: remote hosts' Download/Upload relative to us."""
    if local:
        a = df[df["Direction"] == "Download"].groupby("Source IP")["Size"].sum().rename("Download")
        b = df[df["Direction"] == "Upload"].groupby("Destination IP")["Size"].sum().rename("Upload")
        cols = ["Download", "Upload"]
    else:
        a = df.groupby("Source IP")["Size"].sum().rename("Sent")
        b = df.groupby("Destination IP")["Size"].sum().rename("Received")
        cols = ["Sent", "Received"]
    out = pd.concat([a, b], axis=1).fillna(0).drop(index="Unknown", errors="ignore")
    for c in cols:
        if c not in out:
            out[c] = 0
    out["Total"] = out[cols].sum(axis=1)
    return out, cols


def bandwidth(df, bin_ms, start=None, end=None):
    s = df.set_index("Time")["Size"].resample(f"{bin_ms}ms").sum()
    if start is not None and end is not None:
        idx = pd.date_range(start.floor(f"{bin_ms}ms"), end, freq=f"{bin_ms}ms")
        s = s.reindex(idx, fill_value=0)
    per = s.reset_index()
    per.columns = ["Time", "Bytes"]
    per["Mbps"] = per["Bytes"] * 8 / (bin_ms / 1000) / 1e6
    return per


def render(df, bin_ms, key, live=False, start=None, end=None, total=None,
           local=frozenset(), names=None):
    if df.empty:
        st.warning("No packets match the current filters.")
        return
    names = names or {}
    has_dir = live and bool(local)
    if has_dir:
        df = add_direction(df, local)

    def host_label(ip):
        n = names.get(norm_ip(ip))
        return (f"{n} ({ip})" if n else str(ip))[:48]

    last = df["Time"].max()
    hosts = pd.concat([df["Source IP"], df["Destination IP"]])
    hosts = hosts[hosts != "Unknown"].nunique()
    recent = df[df["Time"] >= (end or last) - pd.Timedelta(seconds=5)] if live else None

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Packets", f"{len(df):,}")
    c2.metric("Data transferred", f"{df['Size'].sum() / 1024:,.1f} KB")
    if has_dir:
        mbps = lambda d: d["Size"].sum() * 8 / 5 / 1e6
        c3.metric("Download (last 5 s)", f"{mbps(recent[recent['Direction'] == 'Download']):.3f} Mbps")
        c4.metric("Upload (last 5 s)", f"{mbps(recent[recent['Direction'] == 'Upload']):.3f} Mbps")
        c5.metric("Unique hosts", hosts)
    elif live:
        c3.metric("Current rate (5 s)", f"{recent['Size'].sum() * 8 / 5 / 1e6:.3f} Mbps")
        c4.metric("Unique hosts", hosts)
        c5.metric("Captured since start", f"{total:,}")
    else:
        dur = (last - df["Time"].min()).total_seconds()
        c3.metric("Duration", f"{dur:.2f} s")
        c4.metric("Avg rate", f"{(df['Size'].sum() * 8 / dur / 1e6) if dur else 0:.2f} Mbps")
        c5.metric("Unique hosts", hosts)

    # ---- classification
    st.subheader("Traffic classification")
    a, b = st.columns(2)
    with a:
        chart(px.pie(df.groupby("Protocol")["Size"].sum().reset_index(),
                     names="Protocol", values="Size", title="By transport protocol (bytes)"),
              f"{key}_proto")
    with b:
        chart(px.pie(df.groupby("Service")["Size"].sum().reset_index(),
                     names="Service", values="Size", title="By service / port (bytes)"),
              f"{key}_service")

    # ---- bandwidth + spikes
    st.subheader("Usage over time")
    per = bandwidth(df, bin_ms, start, end)
    if has_dir:
        frames = [per.assign(Series="Total")]
        for d in ("Download", "Upload"):
            frames.append(bandwidth(df[df["Direction"] == d], bin_ms, start, end).assign(Series=d))
        fig = px.line(pd.concat(frames), x="Time", y="Mbps", color="Series",
                      title=f"Bandwidth ({bin_ms} ms bins)")
        fig.update_traces(line=dict(dash="dot", width=1), selector=dict(name="Total"))
    else:
        fig = px.line(per, x="Time", y="Mbps", title=f"Bandwidth ({bin_ms} ms bins)")
    if len(per) >= 10 and per["Mbps"].std() > 0:
        thr = per["Mbps"].mean() + 2 * per["Mbps"].std()
        spikes = per[per["Mbps"] > thr]
        fig.add_hline(y=thr, line_dash="dash", annotation_text="spike threshold")
        if not spikes.empty:
            fig.add_scatter(x=spikes["Time"], y=spikes["Mbps"], mode="markers",
                            marker=dict(size=10, color="red"), name="Spike")
            st.warning(f"{len(spikes)} traffic spike(s) above {thr:.2f} Mbps "
                       "(mean + 2 standard deviations).")
    chart(fig, f"{key}_bw")

    # ---- top talkers
    st.subheader("Top remote hosts" if has_dir else "Top talkers")
    l, r = st.columns(2)
    hosts_df, cols = host_traffic(df, local if has_dir else frozenset())
    top = hosts_df.nlargest(8, "Total").reset_index(names="Host")
    if not top.empty:
        top["Host"] = top["Host"].map(host_label)
        with l:
            chart(px.bar(top.melt(id_vars="Host", value_vars=cols,
                                  var_name="Direction", value_name="Bytes"),
                         x="Host", y="Bytes", color="Direction", barmode="group",
                         title="Traffic per host (bytes)"),
                  f"{key}_hosts")
    pairs = (df.groupby(["Source IP", "Destination IP"])
             .agg(Packets=("Size", "size"), Total_Bytes=("Size", "sum"))
             .sort_values("Total_Bytes", ascending=False).head(10).reset_index())
    pairs["Pair"] = pairs["Source IP"] + " → " + pairs["Destination IP"]
    with r:
        chart(px.bar(pairs, x="Pair", y="Total_Bytes", title="Busiest conversations (bytes)"),
              f"{key}_pairs")
    if names:
        shown_names = pd.DataFrame(
            [(n, ip) for ip, n in names.items()
             if ip in set(df["Source IP"].map(norm_ip)) | set(df["Destination IP"].map(norm_ip))],
            columns=["Domain (from DNS replies)", "IP address"]).drop_duplicates().head(50)
        if not shown_names.empty:
            with st.expander(f"Domains seen in DNS replies ({len(shown_names)})"):
                table(shown_names)

    # ---- tables
    st.subheader("Summary tables")
    t1, t2 = st.columns(2)
    with t1:
        st.caption("Protocol statistics")
        table(df.groupby("Protocol").agg(Packets=("Size", "size"), Total_Bytes=("Size", "sum"))
              .sort_values("Total_Bytes", ascending=False).reset_index())
    with t2:
        st.caption("Top conversations")
        table(pairs.drop(columns="Pair"))

    st.subheader("Packets")
    shown = df.drop(columns=["Timestamp"])
    if live:
        shown = shown.tail(200).iloc[::-1]
    elif len(shown) > 5000:
        st.caption(f"Showing the first 5,000 of {len(shown):,} packets. The export button has all of them.")
        shown = shown.head(5000)
    table(shown)
    st.download_button("Export filtered packets (CSV)", df.drop(columns=["Timestamp"]).to_csv(index=False),
                       "filtered_packets.csv", "text/csv", key=f"{key}_dl")


# ======================================================================
# Page
# ======================================================================
st.title("Network Traffic Classifier and Usage Dashboard")

UPLOAD, DATASETS, LIVE = "Upload a capture file", "Choose from Datasets folder", "Live capture"
mode = st.sidebar.radio("Data source", [UPLOAD, DATASETS, LIVE])
session = get_session()

st.sidebar.header("Filters")
protos = st.sidebar.multiselect("Protocol", ALL_PROTOCOLS, default=ALL_PROTOCOLS)
services = st.sidebar.multiselect("Service", ALL_SERVICES, default=ALL_SERVICES)
ip_filter = st.sidebar.text_input("IP address (source or destination)")
bin_ms = st.sidebar.select_slider("Bandwidth time bin", options=[10, 50, 100, 250, 500, 1000, 2000],
                                  value=1000 if mode == LIVE else 100, key=f"bin_{mode}",
                                  format_func=lambda v: f"{v} ms")

# ---------------- offline modes ----------------
if mode in (UPLOAD, DATASETS):
    if session.running:
        st.sidebar.warning("A live capture is still running in the background.")
        if st.sidebar.button("Stop live capture"):
            session.stop()
            st.rerun()

    max_packets = st.sidebar.number_input("Max packets to load", 1000, 2_000_000, 100_000, step=10_000,
                                          help="Scapy parses a few thousand packets per second, "
                                               "so very large files take a while.")
    if mode == UPLOAD:
        up = st.file_uploader("Upload a capture file", type=[e.lstrip(".") for e in CAPTURE_EXT])
        if up is None:
            st.info("Upload a .pcap, .pcapng or .cap file to analyse it.")
            st.stop()
        label = up.name
        try:
            raw, truncated, names = parse_upload(up.name, up.getvalue(), int(max_packets))
        except Exception as e:
            st.error(f"Could not read this file: {e}")
            st.stop()
    else:
        files = sorted(f for f in os.listdir(DATASET_DIR) if f.lower().endswith(CAPTURE_EXT))
        if not files:
            st.info(f"No capture files found. Put .pcap / .pcapng / .cap files in:\n\n`{DATASET_DIR}`")
            st.stop()
        label = st.sidebar.selectbox("Capture file", files)
        path = os.path.join(DATASET_DIR, label)
        try:
            raw, truncated, names = parse_path(path, os.path.getmtime(path), int(max_packets))
        except Exception as e:
            st.error(f"Could not read {label}: {e}")
            st.stop()

    st.caption(f"Analysing **{label}**: {len(raw):,} packets loaded"
               + (" (limit reached, increase 'Max packets to load' to see more)" if truncated else ""))
    if raw.empty:
        st.warning("No packets found in this file.")
        st.stop()
    render(apply_filters(raw, protos, services, ip_filter), bin_ms, key="off", names=names)

# ---------------- live mode ----------------
else:
    if not hasattr(st, "fragment"):
        st.error("Live mode needs Streamlit 1.37 or newer:  python -m pip install -U streamlit")
        st.stop()

    st.sidebar.header("Live capture")
    ifaces = list_interfaces()
    by_label = {lbl: (name, ips) for lbl, name, ips in ifaces}
    choice = st.sidebar.selectbox("Network interface", list(by_label), disabled=session.running,
                                  help="The ★ entry is the adapter Windows/Linux uses to reach the "
                                       "internet. Pick that one unless you know better.")
    bpf = st.sidebar.text_input("Capture filter (optional)", placeholder="e.g. tcp port 443",
                                disabled=session.running)
    save_raw = st.sidebar.checkbox("Also save raw packets to Datasets/", disabled=session.running,
                                   help="Writes a .pcap you can reopen later from the Datasets folder.")
    b1, b2 = st.sidebar.columns(2)
    if b1.button("▶ Start", disabled=session.running, type="primary"):
        name, ips = by_label[choice]
        session.start(name, bpf, ips, save_raw)
        st.rerun()
    if b2.button("■ Stop", disabled=not session.running):
        session.stop()
        st.rerun()
    if st.sidebar.button("Clear data"):
        session.clear()
        st.rerun()
    refresh = st.sidebar.slider("Refresh every (seconds)", 1, 10, 2)
    window = st.sidebar.slider("Show last (seconds)", 10, 600, 60)

    with st.expander("Live capture requirements"):
        st.markdown(
            "- **Windows:** install [Npcap](https://npcap.com) and start the terminal "
            "**as Administrator** before running `streamlit`.\n"
            "- **Linux / macOS:** run with `sudo` (or grant capture permissions to Python).\n"
            "- Use the interface marked ★ (your default route), or the one with your real IP address.\n"
            "- Only capture on networks you are allowed to monitor.")

    @st.fragment(run_every=refresh if session.running else None)
    def live_view():
        if session.error:
            st.error(f"Could not start capture. {session.error}\n\n"
                     "Check that the terminal is running as Administrator / with sudo, "
                     "that Npcap is installed (Windows), and that the interface is correct.")
        if session.running:
            secs = max((datetime.now() - session.started_at).total_seconds(), 1)
            st.success(f"● Capturing on **{session.iface}** since {session.started_at:%H:%M:%S}: "
                       f"{session.total:,} packets ({session.total / secs:.0f}/s)"
                       + (f" · saving to `{os.path.basename(session.saved_path)}`" if session.writer else ""))
            if session.total == 0 and secs >= 6:
                st.warning("No packets yet. This interface may be idle or the wrong one. "
                           "Stop, choose the ★ default-route interface, and start again.")
            if session.errors:
                st.caption(f"{session.errors} packet(s) could not be parsed and were skipped.")
        elif session.total:
            st.info(f"Capture stopped. {session.total:,} packets collected."
                    + (f" Raw packets saved to `Datasets/{os.path.basename(session.saved_path)}`."
                       if session.saved_path else ""))
        else:
            st.info("Pick an interface in the sidebar and press ▶ Start.")

        raw, names = session.snapshot()
        if raw.empty:
            return
        end = pd.Timestamp.now() if session.running else raw["Time"].max()
        start = end - pd.Timedelta(seconds=window)
        df = apply_filters(raw[raw["Time"] >= start], protos, services, ip_filter)
        render(df, bin_ms, key="live", live=True, start=start, end=end,
               total=session.total, local=session.local_ips, names=names)

    live_view()