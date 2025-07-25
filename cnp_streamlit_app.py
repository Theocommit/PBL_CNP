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
        G.add
