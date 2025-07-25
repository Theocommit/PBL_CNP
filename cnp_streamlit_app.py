import matplotlib.pyplot as plt
import networkx as nx
import streamlit as st

# Assuming add_osi_log and osi_logs are defined globally
def add_osi_log(layer, message):
    if layer in osi_logs:
        osi_logs[layer].append(message)
    else:
        st.warning(f"Attempted to log to unknown OSI layer: {layer}")

def plot_rip_graph(rip_table, source, target):
    """
    Visualizes the network graph based on RIP routing table using Bellman-Ford algorithm
    and highlights the shortest path from source to target.
    
    Args:
        rip_table (list): List of dictionaries containing routing information
                        Each dict has keys: 'node', 'dest', 'next_hop', 'distance'
        source (int): Source node ID
        target (int): Target node ID
    
    Returns:
        None (Displays graph and path information)
    """
    st.subheader("🌐 RIP Network Graph with Shortest Path (Bellman-Ford)")
    
    # Initialize directed graph
    G = nx.DiGraph()
    
    # Add edges from RIP table
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
        # Compute shortest path using Bellman-Ford
        add_osi_log("Network Layer", f"Computing shortest path from node {source} to node {target} using Bellman-Ford")
        shortest_path = nx.bellman_ford_path(G, source=source, target=target, weight="weight")
        path_edges = list(zip(shortest_path[:-1], shortest_path[1:]))
        
        # Log the shortest path
        add_osi_log("Network Layer", f"Shortest path found: {' -> '.join(map(str, shortest_path))}")
        
        # Prepare graph visualization
        pos = nx.spring_layout(G)
        plt.figure(figsize=(10, 6))
        
        # Draw nodes
        nx.draw_networkx_nodes(G, pos, node_color="lightblue", node_size=500)
        
        # Draw edges
        edge_labels = {(u, v): f"{d['weight']}" for u, v, d in G.edges(data=True)}
        nx.draw_networkx_edges(G, pos, edge_color="gray", arrows=True)
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)
        
        # Highlight shortest path
        nx.draw_networkx_edges TAKE(G, pos, edgelist=path_edges, edge_color="green", width=2, arrows=True)
        
        # Draw node labels
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
