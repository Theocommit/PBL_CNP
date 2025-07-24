from Crypto.Cipher import AES
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import random
import streamlit as st
import tempfile
import time
import pandas as pd
import io

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

# =========================
# AES Encryption w/ Formula
# =========================
def aes_encrypt_visual(data, key):
    pad_len = 16 - (len(data) % 16)
    data_padded = data + bytes([pad_len]) * pad_len
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = [data_padded[i:i+16] for i in range(0, len(data_padded), 16)]
    encrypted_blocks = []

    add_osi_log("Presentation Layer", "--- AES Encryption Started ---")
    add_osi_log("Presentation Layer", f"Original Data Length: {len(data)} bytes")
    add_osi_log("Presentation Layer", f"Padded Data Length: {len(data_padded)} bytes (PKCS#7 padding with {pad_len} bytes)")

    # Detailed log for the first block
    if len(blocks) > 0:
        first_block = blocks[0]
        add_osi_log("Presentation Layer", "\n--- Detailed Encryption for First Block ---")
        add_osi_log("Presentation Layer", f"First Block (Hex): {first_block.hex()}")
        add_osi_log("Presentation Layer", f"AES Key (Hex): {key.hex()}")
        # Simulate encryption of the first block to show intermediate steps if possible
        # (AES ECB is block-by-block, so input/output of block is the main detail)
        encrypted_first_block = cipher.encrypt(first_block)
        add_osi_log("Presentation Layer", f"Encrypted First Block (Hex): {encrypted_first_block.hex()}")
        add_osi_log("Presentation Layer", "--- End Detailed Encryption for First Block ---\n")

    start_enc = time.time()
    for i, block in enumerate(blocks):
        encrypted = cipher.encrypt(block)
        encrypted_blocks.append(encrypted)
        add_osi_log("Presentation Layer", f"Block {i+1} Input:  {block.hex()}")
        add_osi_log("Presentation Layer", f"Block {i+1} Encrypted: {encrypted.hex()}")
        time.sleep(0.05) # Reduced sleep for faster logging
    end_enc = time.time()

    global encryption_time
    encryption_time = end_enc - start_enc
    add_osi_log("Presentation Layer", "--- AES Encryption Finished ---")

    return b"".join(encrypted_blocks)

def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    add_osi_log("Presentation Layer", "--- AES Decryption Started ---")
    add_osi_log("Presentation Layer", f"Ciphertext Length: {len(ciphertext)} bytes")
    if len(ciphertext) % 16 != 0:
        original_len = len(ciphertext)
        ciphertext = ciphertext[:len(ciphertext) - (len(ciphertext) % 16)]
        add_osi_log("Presentation Layer", f"Adjusted Ciphertext Length for decryption: {len(ciphertext)} bytes (removed {original_len - len(ciphertext)} excess bytes)")

    decrypted = cipher.decrypt(ciphertext)
    pad_len = decrypted[-1]
    original_data = decrypted[:-pad_len]
    add_osi_log("Presentation Layer", f"Decrypted Data Length (before unpadding): {len(decrypted)} bytes")
    add_osi_log("Presentation Layer", f"Unpadded Data Length: {len(original_data)} bytes (removed {pad_len} bytes padding)")
    add_osi_log("Presentation Layer", "--- AES Decryption Finished ---")
    return original_data

# ========================
# Character Stuffing Logic
# ========================
def character_stuff(data):
    stuffed = bytearray()
    add_osi_log("Presentation Layer", "--- Character Stuffing Started ---")
    add_osi_log("Presentation Layer", f"Original Data Length (pre-stuffing): {len(data)} bytes")

    # Detailed log for the first few bytes/block of stuffing
    add_osi_log("Presentation Layer", "\n--- Detailed Character Stuffing for First Block/Bytes ---")
    # Assuming we want to show how the first 16 bytes (or less if data is shorter) are stuffed
    sample_data_for_stuffing = data[:min(len(data), 16)]
    add_osi_log("Presentation Layer", f"Sample Input for Stuffing (Hex): {sample_data_for_stuffing.hex()}")
    temp_stuffed_sample = bytearray()
    for byte_val in sample_data_for_stuffing:
        if byte_val == 0x7E: # FLAG byte
            temp_stuffed_sample.append(0x7D) # ESCAPE byte
            temp_stuffed_sample.append(byte_val ^ 0x20) # XOR with 0x20
            add_osi_log("Presentation Layer", f"  Byte 0x{byte_val:02X} (FLAG) stuffed to 0x7D 0x{byte_val ^ 0x20:02X}")
        elif byte_val == 0x7D: # ESCAPE byte
            temp_stuffed_sample.append(0x7D)
            temp_stuffed_sample.append(byte_val ^ 0x20)
            add_osi_log("Presentation Layer", f"  Byte 0x{byte_val:02X} (ESCAPE) stuffed to 0x7D 0x{byte_val ^ 0x20:02X}")
        else:
            temp_stuffed_sample.append(byte_val)
            add_osi_log("Presentation Layer", f"  Byte 0x{byte_val:02X} (Normal) appended as is")
    add_osi_log("Presentation Layer", f"Stuffed Sample Output (Hex): {bytes(temp_stuffed_sample).hex()}")
    add_osi_log("Presentation Layer", "--- End Detailed Character Stuffing ---\n")

    for byte in data:
        if byte == 0x7E: # FLAG byte
            stuffed.append(0x7D) # ESCAPE byte
            stuffed.append(byte ^ 0x20) # XOR with 0x20
            # add_osi_log("Presentation Layer", f"Stuffed FLAG byte (0x7E) -> 0x7D 0x{byte ^ 0x20:02X}") # Moved to detailed log
        elif byte == 0x7D: # ESCAPE byte
            stuffed.append(0x7D)
            stuffed.append(byte ^ 0x20)
            # add_osi_log("Presentation Layer", f"Stuffed ESCAPE byte (0x7D) -> 0x7D 0x{byte ^ 0x20:02X}") # Moved to detailed log
        else:
            stuffed.append(byte)
    add_osi_log("Presentation Layer", f"Stuffed Data Length: {len(stuffed)} bytes")
    add_osi_log("Presentation Layer", "--- Character Stuffing Finished ---")
    return bytes(stuffed)

def character_unstuff(data):
    i = 0
    unstuffed = bytearray()
    add_osi_log("Presentation Layer", "--- Character Unstuffing Started ---")
    add_osi_log("Presentation Layer", f"Stuffed Data Length (pre-unstuffing): {len(data)} bytes")
    while i < len(data):
        if data[i] == 0x7D:
            i += 1
            unstuffed.append(data[i] ^ 0x20)
            add_osi_log("Presentation Layer", f"Unstuffed 0x7D 0x{data[i]:02X} -> 0x{data[i] ^ 0x20:02X}")
        else:
            unstuffed.append(data[i])
        i += 1
    add_osi_log("Presentation Layer", f"Unstuffed Data Length: {len(unstuffed)} bytes")
    add_osi_log("Presentation Layer", "--- Character Unstuffing Finished ---")
    return bytes(unstuffed)

# ========================
# Simulate Bit Errors
# ========================
def simulate_bit_errors(data, error_rate_percent):
    corrupted = bytearray(data)
    num_bits = len(data) * 8
    num_errors = int((error_rate_percent / 100.0) * num_bits)
    
    add_osi_log("Data Link Layer", "--- Bit Error Simulation Started ---")
    add_osi_log("Data Link Layer", f"Original Data Length: {len(data)} bytes ({num_bits} bits)")
    add_osi_log("Data Link Layer", f"Target Error Rate: {error_rate_percent}%")
    add_osi_log("Data Link Layer", f"Number of bits to flip: {num_errors}")

    flipped_bits = 0
    for _ in range(num_errors):
        bit_index = random.randint(0, num_bits - 1)
        byte_index = bit_index // 8
        bit_in_byte = bit_index % 8
        
        original_byte = corrupted[byte_index]
        corrupted[byte_index] ^= 1 << bit_in_byte
        flipped_bits += 1
        add_osi_log("Data Link Layer", f"Flipped bit at global index {bit_index} (Byte {byte_index}, Bit {bit_in_byte}). Original byte: 0x{original_byte:02X}, New byte: 0x{corrupted[byte_index]:02X}")
    
    add_osi_log("Data Link Layer", f"Total bits flipped: {flipped_bits}")
    add_osi_log("Data Link Layer", "--- Bit Error Simulation Finished ---")
    return bytes(corrupted)

# ========================
# TCP Congestion Control
# ========================
def simulate_tcp_on_data(total_packets, ssthresh_init, loss_packets, variant="Tahoe"):
    cwnd = 1
    ssthresh = ssthresh_init
    state = "Slow Start"
    time_series, cwnd_series, ssthresh_series = [], [], []
    ack_series, state_series, transitions = [], [], []

    add_osi_log("Transport Layer", "--- TCP Congestion Control Simulation Started ---")
    add_osi_log("Transport Layer", f"Initial CWND: {cwnd}, Initial SSTHRESH: {ssthresh_init}, TCP Variant: {variant}")
    add_osi_log("Transport Layer", f"Total Packets to simulate: {total_packets}")
    add_osi_log("Transport Layer", f"Pre-defined Loss Packets: {loss_packets}")

    time_step = 0
    i = 0
    while i < total_packets:
        time_series.append(time_step)
        cwnd_series.append(cwnd)
        ssthresh_series.append(int(ssthresh))
        state_series.append(state)
        transitions.append((time_step, cwnd))
        ack_series.append(i)

        log_message = f"Time: {time_step}, CWND: {cwnd}, SSTHRESH: {int(ssthresh)}, State: {state}"

        if i in loss_packets:
            ssthresh = max(cwnd / 2, 1)
            cwnd = 1 if variant == "Tahoe" else max(1, ssthresh)
            state = "Slow Start"
            add_osi_log("Transport Layer", f"{log_message} -> Packet {i} LOST. New SSTHRESH: {int(ssthresh)}, New CWND: {cwnd}, State: {state}")
        else:
            if state == "Slow Start":
                cwnd *= 2
                if cwnd >= ssthresh:
                    state = "Congestion Avoidance"
                add_osi_log("Transport Layer", f"{log_message} -> Packet {i} ACKED. Slow Start. New CWND: {cwnd}, State: {state}")
            elif state == "Congestion Avoidance":
                cwnd += 1
                add_osi_log("Transport Layer", f"{log_message} -> Packet {i} ACKED. Congestion Avoidance. New CWND: {cwnd}")

        i += 1
        time_step += 1
    add_osi_log("Transport Layer", "--- TCP Congestion Control Simulation Finished ---")
    return time_series, cwnd_series, ssthresh_series, ack_series, state_series, transitions

# ========================
# TCP Graph Plot Animation
# ========================
def plot_graphs(time_series, cwnd_series, ssthresh_series, ack_series, transitions):
    chart_placeholder = st.empty()
    for idx in range(1, len(time_series) + 1):
        fig, ax = plt.subplots(2, 1, figsize=(10, 6))

        ax[0].step(time_series[:idx], cwnd_series[:idx], where="post", label="CWND", linewidth=2)
        ax[0].step(time_series[:idx], ssthresh_series[:idx], where="post", linestyle="--", label="SSTHRESH")
        ax[0].set_title("TCP CWND Evolution")
        ax[0].set_xlabel("Time")
        ax[0].set_ylabel("Window Size")
        ax[0].legend()
        ax[0].grid(True)

        ax[1].plot(ack_series[:idx], cwnd_series[:idx], "o-", label="ACKs")
        ax[1].set_title("ACKs and CWND")
        ax[1].set_xlabel("Packet Index")
        ax[1].set_ylabel("CWND")
        ax[1].grid(True)

        chart_placeholder.pyplot(fig)
        plt.close(fig) # Close the figure to prevent memory issues
        time.sleep(0.05) # Reduced sleep for faster animation

# ========================
# RIP Routing + Shortest Path
# ========================
def plot_rip_graph(rip_table, source=None, target=None):
    G = nx.DiGraph()
    add_osi_log("Network Layer", "--- RIP Routing Graph Generation Started ---")
    add_osi_log("Network Layer", "Building graph from RIP table entries:")
    for entry in rip_table:
        src, dst, weight = entry["node"], entry["dest"], entry["distance"]
        G.add_edge(src, dst, weight=weight)
        add_osi_log("Network Layer", f"  Added edge: Node {src} -> Node {dst} (Cost: {weight})")

    pos = nx.spring_layout(G, seed=42)
    labels = nx.get_edge_attributes(G, "weight")

    fig, ax = plt.subplots(figsize=(10, 8))
    
    # Draw all edges first
    nx.draw_networkx_edges(G, pos, edge_color="gray", width=1, ax=ax)
    
    # Draw all nodes
    nx.draw_networkx_nodes(G, pos, node_color="lightblue", node_size=1000, ax=ax)
    
    # Draw labels
    nx.draw_networkx_labels(G, pos, font_size=14, font_weight="bold", ax=ax)
    nx.draw_networkx_edge_labels(G, pos, edge_labels=labels, font_size=10, ax=ax)
    
    if source is not None and target is not None:
        add_osi_log("Network Layer", f"Calculating shortest path from Node {source} to Node {target} using Dijkstra\"s algorithm.")
        try:
            path = nx.dijkstra_path(G, source=source, target=target, weight="weight")
            path_edges = list(zip(path, path[1:]))
            total_distance = nx.dijkstra_path_length(G, source=source, target=target, weight="weight")
            
            add_osi_log("Network Layer", f"Shortest Path Found: {" -> ".join(map(str, path))} (Total Cost: {total_distance})")
            add_osi_log("Network Layer", "Highlighting path on graph.")

            # Highlight shortest path edges with a distinct color, thicker line, and solid style
            nx.draw_networkx_edges(G, pos, edgelist=path_edges, edge_color="red", width=5, style="solid", ax=ax)
            
            # Highlight nodes in the shortest path with different colors
            source_node = [source]
            target_node = [target]
            intermediate_nodes = [node for node in path if node != source and node != target]
            
            nx.draw_networkx_nodes(G, pos, nodelist=source_node, node_color="green", node_size=1200, ax=ax)
            nx.draw_networkx_nodes(G, pos, nodelist=target_node, node_color="red", node_size=1200, ax=ax)
            nx.draw_networkx_nodes(G, pos, nodelist=intermediate_nodes, node_color="yellow", node_size=1100, ax=ax)
            
            # Add title with path information
            ax.set_title(f"RIP Routing Topology\nShortest Path: {" → ".join(map(str, path))}\nTotal Distance: {total_distance}", 
                        fontsize=14, fontweight="bold")
            
            # Add legend
            legend_elements = [
    plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='green', markersize=10, label='Source Node'),
    plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='red', markersize=10, label='Target Node'),
    plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='yellow', markersize=10, label='Intermediate Node'),
    plt.Line2D([0], [0], color='red', linewidth=3, label='Shortest Path')
                ]

            ax.legend(handles=legend_elements, loc=\'upper right\')
            
            st.success(f"🔀 Shortest path from {source} to {target}: {" → ".join(map(str, path))} (Distance: {total_distance})")
            
        except nx.NetworkXNoPath:
            add_osi_log("Network Layer", f"No path found from Node {source} to Node {target}.")
            ax.set_title("RIP Routing Topology", fontsize=14, fontweight="bold")
            st.error(f"❌ No path from {source} to {target}")
    else:
        add_osi_log("Network Layer", "No source or target specified for shortest path calculation.")
        ax.set_title("RIP Routing Topology", fontsize=14, fontweight="bold")
    
    ax.axis(\'off\')
    st.pyplot(fig)
    plt.close(fig) # Close the figure to prevent memory issues
    add_osi_log("Network Layer", "--- RIP Routing Graph Generation Finished ---")

# ========================
# OSI Layer Details
# ========================
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
                "Dijkstra\"s algorithm for shortest path (nx.dijkstra_path)",
                "Graph visualization of network topology"
            ],
            "data_flow": "Receives segments/packets from the Transport Layer. Determines the optimal route for these packets using RIP and Dijkstra\"s algorithm. Passes packets to the Data Link Layer.",
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
        with st.expander(f"**{layer_name}** - {details["data_unit"]}"):
            st.write(f"**Description:** {details["description"]}")
            st.write(f"**Key Functions in Script:**")
            for func in details["functions"]:
                st.markdown(f"- {func}")
            st.write(f"**Data Flow:** {details["data_flow"]}")
            
            if "log_key" in details and osi_logs[details["log_key"]]:
                st.subheader("Real-time Log:")
                for log_entry in osi_logs[details["log_key"]]:
                    st.code(log_entry, language="text")
            elif "log_key" in details:
                st.info(f"No real-time logs available for {details["log_key"]}. Run the simulation to generate logs.")

    # Export OSI Logs to Excel
    st.subheader("📊 Export OSI Logs")
    if st.button("Download OSI Logs as Excel"): # Added a button for clarity
        excel_buffer = io.BytesIO()
        with pd.ExcelWriter(excel_buffer, engine=\'xlsxwriter\') as writer:
            for layer, logs in osi_logs.items():
                if logs:
                    df_log = pd.DataFrame({"Log Entry": logs})
                    df_log.to_excel(writer, sheet_name=layer, index=False)
        excel_buffer.seek(0)
        st.download_button(
            label="Download OSI Logs",
            data=excel_buffer,
            file_name="osi_logs.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

# ========================
# Main Streamlit App
# ========================
def main():
    st.title("🚀 Network Simulation with AES, Stuffing, RIP and TCP")
    
    # ========================
    # SECTION 1: Data Input
    # ========================
    st.header("📄 1. Data Input")
    uploaded_file = st.file_uploader("📂 Upload input text file", type=["txt"])
    if not uploaded_file:
        st.warning("Please upload a .txt file to begin.")
        return

    data = uploaded_file.read().strip()
    st.text_area("📄 Input Data", data.decode(), height=150)

    # ========================
    # SECTION 2: Network Configuration
    # ========================
    st.header("🌐 2. Network Configuration")
    
    col1, col2 = st.columns(2)
    with col1:
        num_nodes = st.number_input("🧝 Number of RIP Nodes", min_value=1, value=3)
        error_rate = st.slider("💥 Bit Error Rate (%)", 0, 100, 0)
    with col2:
        packet_size = st.number_input("📦 MSS (Max Segment Size)", min_value=1, value=64)
        loss_rate = st.slider("📉 Packet Loss Rate (%)", 0, 100, 20)

    # RIP Routing Table Configuration
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

    # Display RIP table
    if rip_table:
        st.subheader("📊 Current RIP Routing Table")
        df_rip = pd.DataFrame(rip_table)
        st.dataframe(df_rip, use_container_width=True)
    else:
        st.info("No RIP entries defined yet.")

    # ========================
    # SECTION 3: Transport Layer Configuration
    # ========================
    st.header("🚛 3. Transport Layer Configuration")
    
    col1, col2 = st.columns(2)
    with col1:
        ssthresh_init = st.number_input("🔧 Initial SSTHRESH", min_value=1, value=8)
    with col2:
        variant = st.selectbox("⚙️ TCP Variant", ["Tahoe", "Reno"])

    # ========================
    # SECTION 4: Path Selection
    # ========================
    st.header("🎯 4. Path Selection")
    
    col1, col2 = st.columns(2)
    with col1:
        source = st.number_input("From Node", min_value=0, value=0)
    with col2:
        target = st.number_input("To Node", min_value=0, value=1)

    # ========================
    # SECTION 5: Run Simulation
    # ========================
    st.header("🚀 5. Run Simulation")
    
    if st.button("🚀 Run Full Network Simulation", type="primary"):
        
        # Clear previous logs
        for layer in osi_logs:
            osi_logs[layer].clear()

        # Calculate loss packets
        loss_packets = sorted(random.sample(range((len(data)+packet_size-1)//packet_size), int((loss_rate / 100) * ((len(data)+packet_size-1)//packet_size))))
        add_osi_log("Physical Layer", f"Configured Bit Error Rate: {error_rate}%")
        add_osi_log("Physical Layer", f"Configured Packet Loss Rate: {loss_rate}%")
        add_osi_log("Physical Layer", f"Total Packets to be sent: {(len(data)+packet_size-1)//packet_size}")
        add_osi_log("Physical Layer", f"Simulated Lost Packets (indices): {loss_packets}")

        # Encryption and stuffing
        key = b"thisisasecretkey"
        encrypted_data = aes_encrypt_visual(data.encode(), key) # Ensure data is bytes
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

        # TCP Simulation
        time_series, cwnd_series, ssthresh_series, ack_series, state_series, transitions = simulate_tcp_on_data(
            total_packets, ssthresh_init, loss_packets, variant)

        st.subheader("📈 TCP CWND Evolution")
        plot_graphs(time_series, cwnd_series, ssthresh_series, ack_series, transitions)

        st.subheader("🌐 RIP Network Graph with Shortest Path")
        plot_rip_graph(rip_table, source, target)

        # Display OSI Log
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

        # ===========================
        # Simulation Metrics Summary
        # ===========================
        total_chunks_sent = total_packets
        successfully_delivered = total_chunks_sent - len(loss_packets)
        lost_packets_count = len(loss_packets)
        avg_latency_per_packet = len(time_series) / total_chunks_sent
        pdr = (successfully_delivered / total_chunks_sent) * 100
        packet_loss_rate = (lost_packets_count / total_chunks_sent) * 100

        st.subheader("📊 Simulation Results")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Chunks Sent", total_chunks_sent)
            st.metric("Successfully Delivered", successfully_delivered)
        with col2:
            st.metric("Lost Packets", lost_packets_count)
            st.metric("Packet Delivery Ratio", f"{pdr:.2f}%")
        with col3:
            st.metric("Packet Loss Rate", f"{packet_loss_rate:.2f}%")
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
    main()
