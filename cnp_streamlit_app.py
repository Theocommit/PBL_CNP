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
    lost_packets_queue = []
    retransmitted_packets = []
    add_osi_log("Transport Layer", "--- TCP Congestion Control Simulation Started ---")
    add_osi_log("Transport Layer", f"Initial CWND: {cwnd}, Initial SSTHRESH: {ssthresh_init}, TCP Variant: {variant}")
    add_osi_log("Transport Layer", f"Total Packets to simulate: {total_packets}")
    add_osi_log("Transport Layer", f"Pre-defined Loss Packets: {loss_packets}")
    add_osi_log("Transport Layer", f"Propagation Delay per Packet: {propagation_delay:.3f} seconds")
    time_step = 0.0
    i = 0
    while i < total_packets:
        time_series.append(time_step)
        cwnd_series.append(cwnd)
        ssthresh_series.append(int(ssthresh))
        state_series.append(state)
        transitions.append((time_step, cwnd))
        ack_series.append(i)
        log_message = f"Time: {time_step:.3f}, CWND: {cwnd:.2f}, SSTHRESH: {int(ssthresh)}, State: {state}"
        if i in loss_packets and i not in retransmitted_packets:
            lost_packets_queue.append(i)
            if last_acked >= 0:
                dup_ack_count[last_acked] = dup_ack_count.get(last_acked, 0) + 1
                add_osi_log("Transport Layer", f"{log_message} -> Packet {i} LOST. Duplicate ACK for packet {last_acked} (Count: {dup_ack_count[last_acked]})")
            else:
                ssthresh = max(int(cwnd / 2), 1)
                cwnd = 1
                state = "Slow Start"
                add_osi_log("Transport Layer", f"{log_message} -> Packet {i} LOST (Timeout). New SSTHRESH: {int(ssthresh)}, New CWND: {cwnd}, State: {state}")
        else:
            if lost_packets_queue and last_acked >= 0:
                for lp in lost_packets_queue[:]:  # Copy to allow modification
                    dup_ack_count[last_acked] = dup_ack_count.get(last_acked, 0) + 1
                    add_osi_log("Transport Layer", f"{log_message} -> Packet {i} ACKED. Duplicate ACK for packet {last_acked} (Count: {dup_ack_count[last_acked]})")
                    if dup_ack_count[last_acked] >= 3 or (time_step - time_series[-1] > 3.0 and not dup_ack_count.get(last_acked, 0)):
                        ssthresh = max(int(cwnd / 2), 1)
                        retransmitted_packets.append(lp)
                        if variant == "Tahoe":
                            cwnd = 1
                            state = "Slow Start"
                        add_osi_log("Transport Layer", f"{log_message} -> {'Fast Retransmit' if dup_ack_count[last_acked] >= 3 else 'Timeout'} for packet {lp}. New SSTHRESH: {int(ssthresh)}, New CWND: {cwnd}, State: {state}")
                        lost_packets_queue.remove(lp)
                        dup_ack_count[last_acked] = 0
                        time_step += 0.1 + propagation_delay
                        i += 1
                        break
            if not lost_packets_queue:
                if state == "Slow Start":
                    cwnd *= 2
                    if cwnd >= ssthresh:
                        state = "Congestion Avoidance"
                    add_osi_log("Transport Layer", f"{log_message} -> Packet {i} ACKED. Slow Start. New CWND: {cwnd}, State: {state}")
                elif state == "Congestion Avoidance":
                    cwnd += 1
                    add_osi_log("Transport Layer", f"{log_message} -> Packet {i} ACKED. Congestion Avoidance. New CWND: {cwnd}")
                last_acked = i
                dup_ack_count[i] = 0
        i += 1
        time_step += 1.0 + propagation_delay
    add_osi_log("Transport Layer", f"Total simulation time: {time_step:.3f} seconds")
    add_osi_log("Transport Layer", f"Retransmitted Packets: {retransmitted_packets}")
    add_osi_log("Transport Layer", "--- TCP Congestion Control Simulation Finished ---")
    return time_series, cwnd_series, ssthresh_series, ack_series, state_series, transitions, retransmitted_packets

def main():
    st.title("🚀 Network Simulation with AES, Stuffing, RIP, and TCP")
    st.header("📄 1. Data Input")
    uploaded_file = st.file_uploader("📂 Upload input text file", type=["txt"])
    if not uploaded_file:
        st.warning("Please upload a .txt file to begin.")
        return
    data = uploaded_file.read().strip()
    st.text_area("📄 Input Data", data.decode(), height=150)
    st.header("🌐 2. Network Configuration")
    col1, col2 = st.columns(2)
    with col1:
        num_nodes = st.number_input("🧝 Number of RIP Nodes", min_value=1, value=3)
        error_rate = st.slider("💥 Bit Error Rate (%)", 0, 100, 0)
    with col2:
        packet_size = st.number_input("📦 MSS (Max Segment Size)", min_value=1, value=64)
        loss_rate = st.slider("📉 Packet Loss Rate (%)", 0, 100, 20)
    st.subheader("📡 RIP Routing Table Configuration")
    rip_table = []
    for i in range(num_nodes):
        with st.expander(f"**Node {i}** Routing Configuration"):
            num_routes = st.number_input(f"Routes for Node {i}", min_value=1, max_value=5, value=2, key=f"r{i}")
            for j in range(num_routes):
                col1, col2, col3 = st.columns(3)
                with col1:
                    dest = st.number_input("Destination", min_value=0, value=0, key=f"d_{i}_{j}")
                with col2:
                    next_hop = st.number_input("Next Hop", min_value=0, value=0, key=f"h_{i}_{j}")
                with col3:
                    distance = st.number_input("Distance", min_value=1, value=1, key=f"dist_{i}_{j}")
                rip_table.append({"node": i, "dest": dest, "next_hop": next_hop, "distance": distance})
    if rip_table:
        st.subheader("📊 Current RIP Routing Table")
        df_rip = pd.DataFrame(rip_table)
        st.dataframe(df_rip, use_container_width=True)
    else:
        st.info("No RIP entries defined yet.")
    st.header("🚛 3. Transport Layer Configuration")
    col1, col2 = st.columns(2)
    with col1:
        ssthresh_init = st.number_input("🔧 Initial SSTHRESH", min_value=1, value=8)
        propagation_delay_ms = st.number_input("⏱️ Propagation Delay per Packet (ms)", min_value=0.0, value=10.0, step=0.1)
    with col2:
        variant = st.selectbox("⚙️ TCP Variant", ["Tahoe", "Reno"], help="Tahoe: Slow Start, Congestion Avoidance, Fast Retransmit. Reno: Adds Fast Recovery.")
    st.header("🎯 4. Path Selection")
    col1, col2 = st.columns(2)
    with col1:
        source = st.number_input("From Node", min_value=0, value=0)
    with col2:
        target = st.number_input("To Node", min_value=0, value=1)
    st.header("🚀 5. Run Simulation")
    if st.button("🚀 Run Full Network Simulation", type="primary"):
        for layer in osi_logs:
            osi_logs[layer].clear()
        total_packets = (len(data) + packet_size - 1) // packet_size
        loss_packets = sorted(random.sample(range(total_packets), int((loss_rate / 100) * total_packets)))
        add_osi_log("Physical Layer", f"Configured Bit Error Rate: {error_rate}%")
        add_osi_log("Physical Layer", f"Configured Packet Loss Rate: {loss_rate}%")
        add_osi_log("Physical Layer", f"Total Packets to be sent: {total_packets}")
        add_osi_log("Physical Layer", f"Simulated Lost Packets (indices): {loss_packets}")
        propagation_delay = propagation_delay_ms / 1000.0
        key = b"thisisasecretkey"
        encrypted_data, encryption_time = aes_encrypt_visual(data, key)
        stuffed_data = character_stuff(encrypted_data)
        if error_rate > 0:
            stuffed_data = simulate_bit_errors(stuffed_data, error_rate)
        total_packets = (len(stuffed_data) + packet_size - 1) // packet_size
        st.subheader("🔐 Encryption & Stuffing Output")
        col1, col2 = st.columns(2)
        with col1:
            st.write(f"**Encrypted Data Length:** {len(encrypted_data)} bytes")
            st.code(encrypted_data.hex()[:200] + "..." if len(encrypted_data.hex()) > 200 else encrypted_data.hex())
        with col2:
            st.write(f"**Stuffed Data Length:** {len(stuffed_data)} bytes")
            st.code(stuffed_data.hex()[:200] + "..." if len(stuffed_data.hex()) > 200 else stuffed_data.hex())
        st.write(f"**Total Packets:** {total_packets}")
        st.write(f"**Lost Packets:** {loss_packets}")
        time_series, cwnd_series, ssthresh_series, ack_series, state_series, transitions, retransmitted_packets = simulate_tcp_on_data(
            total_packets, ssthresh_init, loss_packets, variant, propagation_delay)
        st.subheader("📈 TCP CWND Evolution")
        plot_graphs(time_series, cwnd_series, ssthresh_series, ack_series, transitions)
        st.subheader("🌐 RIP Network Graph with Shortest Path")
        plot_rip_graph(rip_table, source, target)
        display_osi_stack()
        st.subheader("📋 TCP Event Log")
        event_data = []
        for t, c, ssth, state in zip(time_series, cwnd_series, ssthresh_series, state_series):
            event_data.append({
                "Time": f"{t:.2f}",
                "CWND": f"{c:.2f}",
                "SSTHRESH": int(ssth),
                "State": state
            })
        df_events = pd.DataFrame(event_data)
        st.dataframe(df_events, use_container_width=True)
        st.subheader("📤 Receiver Output")
        try:
            start_dec = time.time()
            unstuffed = character_unstuff(stuffed_data)
            decrypted = aes_decrypt(unstuffed, key)
            end_dec = time.time()
            decryption_time = end_dec - start_dec
            st.code(decrypted.decode(errors="ignore"), language="text")
        except Exception as e:
            st.error("Decryption failed: " + str(e))
            decryption_time = 0.0
        total_chunks_sent = total_packets + len(retransmitted_packets)
        successfully_delivered = total_chunks_sent - len(loss_packets)
        lost_packets_count = len(loss_packets)
        avg_latency_per_packet = time_series[-1] / total_chunks_sent if total_chunks_sent > 0 else 0.0
        pdr = (successfully_delivered / total_chunks_sent) * 100 if total_chunks_sent > 0 else 0.0
        packet_loss_rate = (lost_packets_count / total_chunks_sent) * 100 if total_chunks_sent > 0 else 0.0
        st.subheader("📊 Simulation Results")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Chunks Sent", total_chunks_sent)
            st.metric("Successfully Delivered", successfully_delivered)
        with col2:
            st.metric("Lost Packets", lost_packets_count)
            st.metric("Retransmitted Packets", len(retransmitted_packets))
        with col3:
            st.metric("Packet Delivery Ratio", f"{pdr:.2f}%")
            st.metric("Avg Latency/Packet", f"{avg_latency_per_packet:.3f} sec")
        st.subheader("🔐 Encryption/Decryption Overhead")
        col1, col2 = st.columns(2)
        with col1:
            st.write("**Sender Side:**")
            st.write(f"- Total: `{encryption_time:.4f}` sec")
            st.write(f"- Avg per chunk: `{(encryption_time/total_chunks_sent):.4f}` sec")
        with col2:
            st.write("**Receiver Side:**")
            st.write(f"- Total: `{decryption_time:.4f}` sec")
            st.write(f"- Avg per chunk: `{(decryption_time/successfully_delivered):.4f}` sec")

if __name__ == "__main__":
    if platform.system() == "Emscripten":
        asyncio.ensure_future(main())
    else:
        main()
