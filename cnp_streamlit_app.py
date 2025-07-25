import asyncio
import platform
import time
import random
from Crypto.Cipher import AES
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import pandas as pd
import io
import streamlit as st

# Global list to store OSI layer logs
osi_logs = {
    "Application Layer": [],
    "Presentation Layer": [],
    "Session Layer": [],
    "Transport Layer": [],
    "Network Layer": [],
    "Data Link Layer": [],
    "Physical Layer": []
}

def add_osi_log(layer, message):
    if layer in osi_logs:
        osi_logs[layer].append(message)
    else:
        st.warning(f"Attempted to log to unknown OSI layer: {layer}")

def aes_encrypt_visual(data, key):
    start_time = time.time()
    if isinstance(data, str):
        data = data.encode()
    pad_length = 16 - (len(data) % 16)
    data += bytes([pad_length] * pad_length)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(data)
    end_time = time.time()
    encryption_time = end_time - start_time
    add_osi_log("Presentation Layer", f"Encrypted {len(data)} bytes in {encryption_time:.4f} seconds")
    return encrypted, encryption_time

def aes_decrypt(encrypted_data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted_data)
    pad_length = decrypted[-1]
    return decrypted[:-pad_length]

def character_stuff(data):
    FLAG = b'\x7E'
    ESC = b'\x7D'
    stuffed = bytearray()
    stuffed.append(FLAG[0])
    for byte in data:
        if byte in (FLAG[0], ESC[0]):
            stuffed.append(ESC[0])
            stuffed.append(byte ^ 0x20)
        else:
            stuffed.append(byte)
    stuffed.append(FLAG[0])
    add_osi_log("Presentation Layer", f"Stuffed {len(data)} bytes to {len(stuffed)} bytes")
    return bytes(stuffed)

def character_unstuff(stuffed_data):
    FLAG = b'\x7E'
    ESC = b'\x7D'
    unstuffed = bytearray()
    i = 1
    while i < len(stuffed_data) - 1:
        if stuffed_data[i] == ESC[0]:
            i += 1
            unstuffed.append(stuffed_data[i] ^ 0x20)
        else:
            unstuffed.append(stuffed_data[i])
        i += 1
    add_osi_log("Presentation Layer", f"Unstuffed {len(stuffed_data)} bytes to {len(unstuffed)} bytes")
    return bytes(unstuffed)

def simulate_bit_errors(data, error_rate):
    data_bytes = bytearray(data)
    num_errors = int(len(data_bytes) * 8 * (error_rate / 100))
    for _ in range(num_errors):
        byte_index = random.randint(0, len(data_bytes) - 1)
        bit_index = random.randint(0, 7)
        data_bytes[byte_index] ^= (1 << bit_index)
    add_osi_log("Data Link Layer", f"Introduced {num_errors} bit errors ({error_rate}% error rate)")
    return bytes(data_bytes)

def plot_graphs(time_series, cwnd_series, ssthresh_series, ack_series, transitions):
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))
    ax1.plot(time_series, cwnd_series, label="CWND", color="blue")
    ax1.plot(time_series, ssthresh_series, label="SSTHRESH", color="red", linestyle="--")
    ax1.set_xlabel("Time (s)")
    ax1.set_ylabel("Window Size")
    ax1.set_title("TCP Congestion Window Evolution")
    ax1.legend()
    ax1.grid(True)
    ax2.plot(ack_series, cwnd_series, label="CWND", color="blue", marker='o')
    for t, cwnd in transitions:
        packet_idx = next((i for i, ts in enumerate(time_series) if ts >= t), len(time_series) - 1)
        ax2.axvline(x=packet_idx, color="gray", linestyle="--", alpha=0.3)
    ax2.set_xlabel("Packet Index")
    ax2.set_ylabel("CWND")
    ax2.set_title("CWND vs Packet Index")
    ax2.legend()
    ax2.grid(True)
    plt.tight_layout()
    st.pyplot(fig)

def plot_rip_graph(rip_table, source, target):
    st.subheader("🌐 RIP Network Graph with Shortest Path (Bellman-Ford)")
    G = nx.DiGraph()
    add_osi_log("Network Layer", "Constructing network topology from RIP routing table")
    for entry in rip_table:
        node = entry["node"]
        dest = entry["dest"]
        distance = entry["distance"]
        next_hop = entry["next_hop"]
        G.add_edge(node, next_hop, weight=distance, dest=dest)
        add_osi_log("Network Layer", f"Added edge: {node} -> {next_hop} (dest: {dest}, weight: {distance})")
    if not G.nodes():
        st.error("No nodes defined in the RIP table.")
        return
    try:
        add_osi_log("Network Layer", f"Computing shortest path from node {source} to node {target} using Bellman-Ford")
        shortest_path = nx.bellman_ford_path(G, source=source, target=target, weight="weight")
        path_edges = list(zip(shortest_path[:-1], shortest_path[1:]))
        add_osi_log("Network Layer", f"Shortest path found: {' -> '.join(map(str, shortest_path))}")
        pos = nx.spring_layout(G)
        plt.figure(figsize=(10, 6))
        nx.draw_networkx_nodes(G, pos, node_color="lightblue", node_size=500)
        edge_labels = {(u, v): f"{d['weight']}" for u, v, d in G.edges(data=True)}
        nx.draw_networkx_edges(G, pos, edge_color="gray", arrows=True)
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)
        nx.draw_networkx_edges(G, pos, edgelist=path_edges, edge_color="green", width=2, arrows=True)
        nx.draw_networkx_labels(G, pos, font_size=12, font_weight="bold")
        st.pyplot(plt)
        st.success(f"Shortest Path: {' -> '.join(map(str, shortest_path))}")
    except nx.NetworkXNoPath:
        st.error(f"No path exists between node {source} and node {target}.")
        add_osi_log("Network Layer", f"No path exists between node {source} and node {target}")
    except nx.NodeNotFound as e:
        st.error(f"Node not found in the graph: {e}")
        add_osi_log("Network Layer", f"Node not found: {e}")
    except nx.NetworkXNegativeCycle:
        st.error("Negative cycle detected in the graph. Bellman-Ford cannot proceed.")
        add_osi_log("Network Layer", "Negative cycle detected in the graph")

def display_osi_stack():
    st.subheader("🌐 OSI Model Stack")
    osi_layers_details = {
        "7. Application Layer": {
            "description": "Provides network services directly to end-user applications. Handles high-level protocols, data formatting, and user interfaces.",
            "data_unit": "Data",
            "functions": [
                "User interaction through Streamlit UI (main function)",
                "Input of simulation parameters (st.number_input, st.selectbox, st.slider)",
                "Display of simulation results (st.subheader, st.write, st.code, st.markdown)"
            ],
            "data_flow": "User data (e.g., text input, configuration choices) is passed down to the Presentation Layer."
        },
        "6. Presentation Layer": {
            "description": "Responsible for data translation, encryption, decryption, and compression. Ensures that data is in a readable format for the Application Layer.",
            "data_unit": "Data",
            "functions": [
                "AES Encryption/Decryption (aes_encrypt_visual, aes_decrypt)",
                "Character Stuffing/Unstuffing (character_stuff, character_unstuff)"
            ],
            "data_flow": "Receives user data from the Application Layer. Encrypts and stuffs the data, then passes the formatted data to the Session Layer.",
            "log_key": "Presentation Layer"
        },
        "5. Session Layer": {
            "description": "Establishes, manages, and terminates communication sessions between applications. Handles dialogue control and synchronization.",
            "data_unit": "Data",
            "functions": [
                "Implicit session management through Streamlit application state and flow"
            ],
            "data_flow": "Receives formatted data from the Presentation Layer. Manages the ongoing interaction session and passes data to the Transport Layer."
        },
        "4. Transport Layer": {
            "description": "Provides reliable and transparent transfer of data between end systems. Handles segmentation, reassembly, flow control, and error recovery.",
            "data_unit": "Segments",
            "functions": [
                "TCP Congestion Control Simulation (simulate_tcp_on_data)",
                "CWND and SSTHRESH management",
                "Graph plotting of TCP evolution (plot_graphs)"
            ],
            "data_flow": "Receives data from the Session Layer. Segments the data into packets (implicitly, as the simulation deals with total packets) and applies TCP congestion control logic. Passes segments/packets to the Network Layer.",
            "log_key": "Transport Layer"
        },
        "3. Network Layer": {
            "description": "Responsible for logical addressing and routing of data packets across different networks. It determines the best path for data delivery.",
            "data_unit": "Packets",
            "functions": [
                "RIP Routing (plot_rip_graph)",
                "Bellman-Ford algorithm for shortest path (nx.bellman_ford_path)",
                "Graph visualization of network topology"
            ],
            "data_flow": "Receives segments/packets from the Transport Layer. Determines the optimal route for these packets using RIP and Bellman-Ford algorithm. Passes packets to the Data Link Layer.",
            "log_key": "Network Layer"
        },
        "2. Data Link Layer": {
            "description": "Provides reliable data transfer across a physical link. It handles framing, physical addressing (MAC addresses), error detection, and flow control within a local network segment.",
            "data_unit": "Frames",
            "functions": [
                "Bit Error Simulation (simulate_bit_errors)"
            ],
            "data_flow": "Receives packets from the Network Layer. Simulates bit errors that might occur during transmission. Passes frames (with potential errors) to the Physical Layer.",
            "log_key": "Data Link Layer"
        },
        "1. Physical Layer": {
            "description": "Defines the physical characteristics of the network, including cabling, connectors, and electrical signals. It deals with the raw bit stream transmission.",
            "data_unit": "Bits",
            "functions": [
                "Implicit simulation of physical medium characteristics (packet_size, error_rate)"
            ],
            "data_flow": "Receives frames from the Data Link Layer. Converts them into raw bit streams for transmission over the simulated physical medium. The `error_rate` directly influences the integrity of these bits.",
            "log_key": "Physical Layer"
        }
    }
    for layer_name, details in osi_layers_details.items():
        with st.expander(f"**{layer_name}** - {details['data_unit']}"):
            st.write(f"**Description:** {details['description']}")
            st.write(f"**Key Functions in Script:**")
            for func in details['functions']:
                st.markdown(f"- {func}")
            st.write(f"**Data Flow:** {details['data_flow']}")
            if 'log_key' in details and osi_logs[details['log_key']]:
                st.subheader("Real-time Log:")
                for log_entry in osi_logs[details['log_key']]:
                    st.code(log_entry, language="text")
            elif 'log_key' in details:
                st.info(f"No real-time logs available for {details['log_key']}. Run the simulation to generate logs.")
    st.subheader("📊 Export OSI Logs")
    has_logs = any(logs for logs in osi_logs.values())
    if has_logs:
        excel_buffer = io.BytesIO()
        with pd.ExcelWriter(excel_buffer, engine='xlsxwriter') as writer:
            for layer, logs in osi_logs.items():
                if logs:
                    safe_sheet_name = layer.replace(" Layer", "").replace(".", "").strip()[:31]
                    df_log = pd.DataFrame({"Log Entry": logs})
                    df_log.to_excel(writer, sheet_name=safe_sheet_name, index=False)
            writer.close()
        excel_buffer.seek(0)
        st.download_button(
            label="Download OSI Logs",
            data=excel_buffer,
            file_name="osi_logs.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            key="download_osi_logs"
        )
    else:
        st.warning("No logs available to export. Please run the simulation first.")

def simulate_tcp_on_data(total_packets, ssthresh_init, loss_packets, variant="Tahoe", propagation_delay=0.0):
    cwnd = 1
    ssthresh = ssthresh_init
    state = "Slow Start"
    time_series, cwnd_series, ssthresh_series = [], [], []
    ack_series, state_series, transitions = [], [], []
    dup_ack_count = {}
    last_acked = -1
    lost_packet = None  # Track the most recent lost packet
    retransmitted_packets = []
    add_osi_log("Transport Layer", "--- TCP Congestion Control Simulation Started ---")
    add_osi_log("Transport Layer", f"Initial CWND: {cwnd}, Initial SSTHRESH: {ssth
