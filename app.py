"""
Network Traffic Classifier and Usage Dashboard
Reads the CSV files produced by main.py / analytics.py.
Run with:  streamlit run app.py
"""
import os
import pandas as pd
import plotly.express as px
import streamlit as st

st.set_page_config(page_title="Network Traffic Dashboard", layout="wide")
BASE = os.path.dirname(os.path.abspath(__file__))

# Well-known ports -> service name (application-level classification by port)
PORT_SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    161: "SNMP", 443: "HTTPS", 445: "SMB", 587: "SMTP", 631: "IPP (printing)",
    993: "IMAPS", 3306: "MySQL", 3389: "RDP", 5060: "SIP", 8080: "HTTP-alt",
}


def service_of(row):
    """Classify by the lower (well-known) port of the two endpoints."""
    ports = [p for p in (row["Source Port"], row["Destination Port"]) if pd.notna(p)]
    if not ports:
        return "No port (non-TCP/UDP)"
    known = [PORT_SERVICES[int(p)] for p in ports if int(p) in PORT_SERVICES]
    return known[0] if known else "Other / ephemeral"


@st.cache_data
def read(name):
    return pd.read_csv(os.path.join(BASE, name))


@st.cache_data
def load_packets():
    df = read("packet_analysis.csv").rename(columns={"Packet Size (bytes)": "Size"})
    df["Time"] = pd.to_datetime(df["Timestamp"], unit="s")
    if "Service" not in df.columns:      # older CSVs made before main.py added it
        df["Service"] = df.apply(service_of, axis=1)
    return df


try:
    packets = load_packets()
    proto_stats = read("protocol_stats.csv")
    top_src = read("top_sources.csv")
    top_dst = read("top_destinations.csv")
    top_pairs = read("top_pairs.csv")
except FileNotFoundError as e:
    st.error(f"Missing file: {e.filename}. Put app.py in the same folder as the CSVs.")
    st.stop()

st.title("Network Traffic Classifier and Usage Dashboard")

# ---------------- Sidebar filters ----------------
st.sidebar.header("Filters")
all_protos = sorted(packets["Protocol"].unique())
protos = st.sidebar.multiselect("Protocol", all_protos, default=all_protos)
all_services = sorted(packets["Service"].unique())
services = st.sidebar.multiselect("Service", all_services, default=all_services)
ip = st.sidebar.text_input("Filter by IP address (source or destination)")
bin_ms = st.sidebar.select_slider("Time bin for bandwidth chart",
                                  options=[10, 50, 100, 250, 500, 1000], value=100,
                                  format_func=lambda v: f"{v} ms")

df = packets[packets["Protocol"].isin(protos) & packets["Service"].isin(services)]
if ip:
    df = df[(df["Source IP"] == ip) | (df["Destination IP"] == ip)]
if df.empty:
    st.warning("No packets match these filters.")
    st.stop()

# ---------------- Summary cards ----------------
duration = (df["Time"].max() - df["Time"].min()).total_seconds()
total_bytes = df["Size"].sum()
hosts = pd.concat([df["Source IP"], df["Destination IP"]])
hosts = hosts[hosts != "Unknown"].nunique()

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total packets", f"{len(df):,}")
c2.metric("Data transferred", f"{total_bytes / 1024:,.1f} KB")
c3.metric("Duration", f"{duration:.2f} s")
c4.metric("Avg rate", f"{(total_bytes * 8 / duration / 1e6) if duration else 0:.2f} Mbps")
c5.metric("Unique hosts", hosts)

# ---------------- Classification ----------------
st.subheader("Traffic classification")
a, b = st.columns(2)
a.plotly_chart(px.pie(df.groupby("Protocol")["Size"].sum().reset_index(),
                      names="Protocol", values="Size", title="By transport protocol (bytes)"),
               use_container_width=True)
b.plotly_chart(px.pie(df.groupby("Service")["Size"].sum().reset_index(),
                      names="Service", values="Size", title="By service / port (bytes)"),
               use_container_width=True)

# ---------------- Bandwidth over time ----------------
st.subheader("Usage over time")
per = (df.set_index("Time")["Size"].resample(f"{bin_ms}ms").sum().reset_index())
per["Mbps"] = per["Size"] * 8 / (bin_ms / 1000) / 1e6
fig = px.line(per, x="Time", y="Mbps", title=f"Bandwidth ({bin_ms} ms bins)")

# Simple anomaly detection: flag bins above mean + 2 * std
thr = per["Mbps"].mean() + 2 * per["Mbps"].std()
spikes = per[per["Mbps"] > thr] if pd.notna(thr) else per.iloc[0:0]
fig.add_hline(y=thr, line_dash="dash", annotation_text="spike threshold")
if not spikes.empty:
    fig.add_scatter(x=spikes["Time"], y=spikes["Mbps"], mode="markers",
                    marker=dict(size=10, color="red"), name="Spike")
st.plotly_chart(fig, use_container_width=True)
if spikes.empty:
    st.success("No traffic spikes detected (threshold = mean + 2 standard deviations).")
else:
    st.warning(f"{len(spikes)} traffic spike(s) detected above {thr:.2f} Mbps.")

# ---------------- Top talkers ----------------
st.subheader("Top talkers")
l, m, r = st.columns(3)
l.plotly_chart(px.bar(top_src, x="Source IP", y="Total_Bytes", title="Top sources"),
               use_container_width=True)
m.plotly_chart(px.bar(top_dst, x="Destination IP", y="Total_Bytes", title="Top destinations"),
               use_container_width=True)
pairs = top_pairs.assign(Pair=top_pairs["Source IP"] + " → " + top_pairs["Destination IP"])
r.plotly_chart(px.bar(pairs, x="Pair", y="Total_Bytes", title="Top conversations"),
               use_container_width=True)

# Upload vs download for a chosen host
known = sorted(h for h in set(df["Source IP"]) | set(df["Destination IP"]) if h != "Unknown")
if known:
    host = st.selectbox("Upload vs download for host", known)
    up = df.loc[df["Source IP"] == host, "Size"].sum()
    down = df.loc[df["Destination IP"] == host, "Size"].sum()
    st.plotly_chart(px.bar(pd.DataFrame({"Direction": ["Upload (sent)", "Download (received)"],
                                         "Bytes": [up, down]}),
                           x="Direction", y="Bytes", title=f"{host}: sent vs received"),
                    use_container_width=True)

# ---------------- Tables ----------------
st.subheader("Summary tables")
t1, t2 = st.columns(2)
t1.write("Protocol statistics")
t1.dataframe(proto_stats, use_container_width=True, hide_index=True)
t2.write("Top conversations")
t2.dataframe(top_pairs, use_container_width=True, hide_index=True)

st.subheader("Packet table")
st.dataframe(df.drop(columns=["Timestamp"]), use_container_width=True, hide_index=True)
st.download_button("Export filtered packets (CSV)", df.to_csv(index=False),
                   "filtered_packets.csv", "text/csv")
