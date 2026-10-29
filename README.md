# Network Traffic Classifier and Usage Dashboard: Commands Guide

Everything now runs from one web page. Run all commands from inside the `CN_project` folder.

## Project layout

```
CN_project/
├── Datasets/        # put your .pcap / .pcapng / .cap files here
├── app.py           # the whole dashboard (upload, Datasets folder, live capture)
├── main.py          # optional: command-line packet analysis -> CSV
├── analytics.py     # optional: summary CSVs from main.py output
└── COMMANDS.md
```

`live_capture.py` and `live_dashboard.py` are no longer needed, because live capture is built into `app.py`.

## 1. One-time setup

```
python -m pip install scapy pandas plotly streamlit
```

Windows only, for live capture: install **Npcap** from https://npcap.com (default options).

## 2. Start the dashboard

```
python -m streamlit run app.py
```

For **live capture**, start the terminal first as **Administrator** on Windows, or use `sudo python3 -m streamlit run app.py` on Linux/macOS. For uploaded and Datasets files, a normal terminal is fine.

The page opens at http://localhost:8501. Stop it with `Ctrl+C`.

## 3. Using the page

Pick a **Data source** in the sidebar:

| Source | What to do |
|---|---|
| Upload a capture file | Drag in a .pcap, .pcapng or .cap file |
| Choose from Datasets folder | Select a file from the dropdown (files you put in `Datasets/`) |
| Live capture | Keep the interface marked ★ (your default route), press ▶ Start, press ■ Stop when done |

Sidebar options:

- **Protocol / Service / IP filters** narrow every chart and table.
- **Bandwidth time bin** changes the resolution of the bandwidth chart.
- **Max packets to load** (offline modes) limits how much of a large file is parsed.
- **Capture filter** (live mode) is an optional filter such as `tcp port 443`.
- **Also save raw packets to Datasets/** (live mode) writes a `.pcap` you can reopen later from the Datasets dropdown.
- **Refresh every / Show last** (live mode) control the auto-refresh and the time window.
- **Clear data** (live mode) empties the live buffer.
- **Export** button under the packet table downloads the filtered packets as CSV.

### Live capture extras

- The interface list puts the adapter with your default route first (★) and moves virtual, Bluetooth and no-network adapters to the bottom.
- Download and upload are shown separately (relative to your machine's IP), both as cards and as lines on the bandwidth chart.
- "Top remote hosts" shows domain names when the matching DNS reply was captured, for example `youtube.com (142.250.80.46)`. Encrypted DNS (DoH/DoT) hides these.
- If no packets arrive within a few seconds, the page warns that the interface is probably wrong.

## 4. Optional command-line analysis

```
python main.py SkypeIRC.cap      # looks inside Datasets/, writes packet_analysis.csv
python analytics.py              # writes the summary CSV files
```

## 5. Troubleshooting

| Problem | Fix |
|---|---|
| `streamlit` is not recognized | Use `python -m streamlit run app.py` |
| `No module named ...` | `python -m pip install scapy pandas plotly streamlit` |
| Live: "Could not start capture" | Run the terminal as Administrator / with `sudo`, install Npcap (Windows) |
| Live: 0 packets | Choose the ★ interface, or the one that shows your real IP (Wi-Fi or Ethernet), not Bluetooth or virtual adapters |
| Live: filter error | Capture filters need Npcap/libpcap. Leave the filter empty if unsure |
| Live mode asks for a newer Streamlit | `python -m pip install -U streamlit` |
| No files in Datasets dropdown | Put the files in the `Datasets` folder next to `app.py` and refresh |
| Large file is slow | Lower "Max packets to load". Scapy parses a few thousand packets per second |

## 6. Limitations

- Services are identified by port number only. HTTPS is encrypted, so the exact application is not visible.
- Traffic on non-standard ports is labelled "Other / ephemeral".
- Only capture on networks you are authorised to monitor.
