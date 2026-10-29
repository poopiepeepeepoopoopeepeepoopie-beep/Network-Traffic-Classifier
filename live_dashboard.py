"""
Live dashboard: reads live_packets.csv written by live_capture.py and refreshes itself.
Run with:  python -m streamlit run live_dashboard.py
Needs Streamlit >= 1.37  (pip install -U streamlit)
"""
import os
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

st.set_page_config(page_title="Live Network Traffic", layout="wide")
FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "live_packets.csv")
LOCAL_TZ = datetime.now().astimezone().tzinfo

st.title("Live Network Traffic Monitor")
st.sidebar.header("Settings")
refresh = st.sidebar.slider("Refresh every (seconds)", 1, 10, 2)
window = st.sidebar.slider("Show last (seconds)", 10, 600, 60)
st.sidebar.caption("Start capture first:  python live_capture.py")


def load():
    if not os.path.exists(FILE):
        return None
    try:
        df = pd.read_csv(FILE)
    except Exception:                      # file caught mid-write: try again next refresh
        return None
    if df.empty:
        return None
    df = df.rename(columns={"Packet Size (bytes)": "Size"})
    df["Time"] = (pd.to_datetime(df["Timestamp"], unit="s", utc=True)
                  .dt.tz_convert(LOCAL_TZ).dt.tz_localize(None))
    return df


@st.fragment(run_every=refresh)
def live_view():
    df = load()
    if df is None:
        st.info("Waiting for packets... start `python live_capture.py` in another terminal.")
        return

    latest = df["Time"].max()
    df = df[df["Time"] >= latest - pd.Timedelta(seconds=window)]

    # current rate = last 5 seconds
    recent = df[df["Time"] >= latest - pd.Timedelta(seconds=5)]
    rate = recent["Size"].sum() * 8 / 5 / 1e6

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Packets (window)", f"{len(df):,}")
    c2.metric("Data (window)", f"{df['Size'].sum() / 1024:,.1f} KB")
    c3.metric("Current rate (5 s)", f"{rate:.3f} Mbps")
    c4.metric("Last packet", latest.strftime("%H:%M:%S"))

    per = df.set_index("Time")["Size"].resample("1s").sum().reset_index()
    per["Mbps"] = per["Size"] * 8 / 1e6
    fig = px.line(per, x="Time", y="Mbps", title="Bandwidth (1 s bins)")

    # spike alert: needs enough history to be meaningful
    if len(per) >= 10:
        thr = per["Mbps"].mean() + 2 * per["Mbps"].std()
        spikes = per[per["Mbps"] > thr]
        fig.add_hline(y=thr, line_dash="dash", annotation_text="spike threshold")
        if not spikes.empty:
            fig.add_scatter(x=spikes["Time"], y=spikes["Mbps"], mode="markers",
                            marker=dict(size=10, color="red"), name="Spike")
            st.warning(f"{len(spikes)} traffic spike(s) in this window.")
    st.plotly_chart(fig, use_container_width=True, key="bw")

    a, b = st.columns(2)
    a.plotly_chart(px.pie(df.groupby("Service")["Size"].sum().reset_index(),
                          names="Service", values="Size", title="By service (bytes)"),
                   use_container_width=True, key="svc")
    talkers = (df.groupby("Source IP")["Size"].sum().nlargest(8).reset_index())
    b.plotly_chart(px.bar(talkers, x="Source IP", y="Size", title="Top sources (bytes)"),
                   use_container_width=True, key="top")

    st.subheader("Latest packets")
    st.dataframe(df.drop(columns=["Timestamp"]).tail(30).iloc[::-1],
                 use_container_width=True, hide_index=True)


live_view()