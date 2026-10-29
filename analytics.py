
import pandas as pd

# Load the packet data created by main.py
df = pd.read_csv("packet_analysis.csv")

if df.empty:
    print("No packet records found.")
    raise SystemExit

# Convert packet timestamps to readable dates
df["Timestamp"] = pd.to_datetime(
    df["Timestamp"], unit="s"
)

# 1. Protocol statistics
protocol_stats = df.groupby("Protocol").agg(
    Packet_Count=("Protocol", "size"),
    Total_Bytes=("Packet Size (bytes)", "sum")
).sort_values("Total_Bytes", ascending=False)

print("\n=== PROTOCOL STATISTICS ===")
print(protocol_stats)

# 2. Traffic volume per second
df["Time_Interval"] = df["Timestamp"].dt.floor("s")

traffic_over_time = df.groupby("Time_Interval").agg(
    Packet_Count=("Protocol", "size"),
    Total_Bytes=("Packet Size (bytes)", "sum")
)

print("\n=== TRAFFIC PER SECOND ===")
print(traffic_over_time.head(20))

# 3. Top source IP addresses
top_sources = df.groupby("Source IP").agg(
    Packets=("Protocol", "size"),
    Total_Bytes=("Packet Size (bytes)", "sum")
).sort_values("Total_Bytes", ascending=False)

print("\n=== TOP SOURCE IPs ===")
print(top_sources.head(10))

# 4. Top destination IP addresses
top_destinations = df.groupby("Destination IP").agg(
    Packets=("Protocol", "size"),
    Total_Bytes=("Packet Size (bytes)", "sum")
).sort_values("Total_Bytes", ascending=False)

print("\n=== TOP DESTINATION IPs ===")
print(top_destinations.head(10))

# 5. Common source-destination pairs
top_pairs = df.groupby(
    ["Source IP", "Destination IP"]
).agg(
    Packets=("Protocol", "size"),
    Total_Bytes=("Packet Size (bytes)", "sum")
).sort_values("Total_Bytes", ascending=False)

print("\n=== TOP COMMUNICATION PAIRS ===")
print(top_pairs.head(10))

# Save summaries for future use
protocol_stats.to_csv("protocol_stats.csv")
traffic_over_time.to_csv("traffic_over_time.csv")
top_sources.to_csv("top_sources.csv")
top_destinations.to_csv("top_destinations.csv")
top_pairs.to_csv("top_pairs.csv")

print("\nAll analytics reports saved successfully.")
