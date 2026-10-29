# Network Traffic Classifier and Usage Dashboard: Commands Guide

All commands are run from inside the `CN_project` folder (PowerShell or terminal).

## Project layout

```
CN_project/
├── Datasets/            # put your .pcap / .cap files here
├── main.py              # reads a pcap, classifies packets -> packet_analysis.csv
├── analytics.py         # builds summary CSVs from packet_analysis.csv
├── app.py               # dashboard for captured files (offline analysis)
├── live_capture.py      # live packet capture -> live_packets.csv
├── live_dashboard.py    # auto-refreshing dashboard for live capture
└── COMMANDS.md          # this file
```

## 1. One-time setup

Install Python 3.9 or newer, then:

```
python -m pip install scapy pandas plotly streamlit
```

For live capture on Windows, also install **Npcap** from https://npcap.com (default options are fine).

Check that everything installed:

```
python -m pip show scapy streamlit plotly pandas
```

## 2. Analyze a capture file (offline)

Put the capture in `Datasets/`, then run these three commands in order:

```
python main.py SkypeIRC.cap
python analytics.py
python -m streamlit run app.py
```

| Command | What it does |
|---|---|
| `python main.py <file>` | Reads the file from `Datasets/`, classifies each packet, writes `packet_analysis.csv` |
| `python analytics.py` | Creates `protocol_stats.csv`, `traffic_over_time.csv`, `top_sources.csv`, `top_destinations.csv`, `top_pairs.csv` |
| `python -m streamlit run app.py` | Opens the dashboard in your browser (usually http://localhost:8501) |

If you don't give a file name, `main.py` uses `traffic.pcap`.

To analyze a different file, repeat all three steps, then refresh the browser page.

## 3. Live capture

Use two terminals, both inside `CN_project`.

**Terminal 1** (open as **Administrator** on Windows, or use `sudo` on Linux/macOS):

```
python live_capture.py --list
python live_capture.py --iface "Wi-Fi"
```

**Terminal 2:**

```
python -m streamlit run live_dashboard.py
```

Browse the web or play a video and watch the dashboard update. Press `Ctrl+C` in Terminal 1 to stop capturing.

### Live capture options

| Option | Example | Meaning |
|---|---|---|
| `--list` | `python live_capture.py --list` | Show network interfaces and exit |
| `--iface` | `--iface "Ethernet"` | Choose the interface to capture on |
| `--duration` | `--duration 60` | Stop automatically after 60 seconds |
| `--filter` | `--filter "tcp port 443"` | Capture only matching traffic (BPF filter) |
| `--offline` | `--offline Datasets/traffic.pcap` | Replay a file instead of sniffing (for testing) |

Only capture on your own computer or on a network you are authorized to monitor.

## 4. Using the dashboard

- **Sidebar filters:** protocol, service, and IP address.
- **Time bin slider:** changes the resolution of the bandwidth chart (`app.py`).
- **Export CSV button:** downloads the currently filtered packets.
- **Spike detection:** a point is flagged when its bandwidth is above the mean plus 2 standard deviations.
- Stop the dashboard with `Ctrl+C` in its terminal.

## 5. Troubleshooting

| Problem | Fix |
|---|---|
| `streamlit` is not recognized | Use `python -m streamlit run app.py` instead |
| `No module named ...` | Run `python -m pip install scapy pandas plotly streamlit` |
| `File not found` from `main.py` | Check the file is inside `Datasets/` and the name is spelled correctly |
| Dashboard shows old data | Re-run `main.py` and `analytics.py`, then refresh the page |
| Live capture shows 0 packets | Run the terminal as Administrator, make sure Npcap is installed, and pick the correct interface with `--list` |
| `Permission denied` | Run the terminal as Administrator (or use `sudo`) |
| Live dashboard says "Waiting for packets" | Start `live_capture.py` first, from the same folder |
| `st.fragment` error in live dashboard | Update Streamlit: `python -m pip install -U streamlit` |
| Charts look empty for a small capture | Normal for captures that last only a second or two. Try `SkypeIRC.cap` or a longer file |

## 6. Limitations

- Services are identified by port number only. HTTPS traffic is encrypted, so the exact application cannot be determined.
- Traffic on non-standard ports is labelled "Other / ephemeral".
- Offline analysis works on one capture file at a time.
