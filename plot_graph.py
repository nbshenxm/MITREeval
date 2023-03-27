import networkx as nx
import matplotlib.pyplot as plt
import numpy as np
from networkx.drawing.nx_agraph import graphviz_layout

# Define the connectivity matrix
wizard_spider_connectivity = {
    0: [1, 2],
    1: [0],
    2: [0, 3],
    3: [2, 5, 6],
    # 4: [],
    5: [3],
    6: [3, 7],
    7: [6, 8],
    8: [7, 9, 11, 12, 13, 14, 15, 16],
    9: [8],
    # 10: [],
    11: [8],
    12: [8],
    13: [8],
    14: [8],
    15: [8],
    16: [8],
    17: [19, 20],
    # 18: [],
    19: [17, 20, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31],
    20: [17, 19],
    # 21: [],
    22: [19],
    23: [19],
    24: [19],
    25: [19],
    26: [19],
    27: [19],
    28: [19],
    29: [19],
    30: [19],
    31: [19, 32],
    32: [31],
    33: [35, 36, 37, 38, 39],
    # 34: [],
    35: [33],
    36: [33],
    37: [33],
    38: [33, 40, 41, 42, 43, 44, 45],
    39: [33],
    40: [38],
    41: [38],
    42: [38],
    43: [38],
    44: [38],
    45: [38, 46, 47, 48, 49, 50, 51],
    46: [45],
    47: [45],
    48: [45],
    49: [45],
    50: [45],
    51: [45]}

sandworm_connectivity = {
    0: [2],
    # 1: [],
    2: [0, 3],
    3: [2, 4],
    4: [3, 5, 6, 7, 8],
    5: [4],
    6: [4],
    7: [4],
    8: [4],
    9: [4, 10],
    10: [9, 11, 14, 15, 16, 17, 18],
    11: [10],
    # 12: [],
    # 13: [],
    14: [10],
    15: [10],
    16: [10],
    17: [10],
    18: [10],
    19: [21, 22],
    # 20: [],
    21: [19, 26],
    22: [19, 23],
    23: [22, 24],
    24: [23, 25, 26],
    25: [24],
    26: [21, 24, 27, 29, 30, 31, 32, 34, 36, 38, 39, 40, 41],
    27: [26],
    # 28: [],
    29: [26],
    30: [26],
    31: [26],
    32: [26, 33],
    33: [32],
    34: [26, 35, 41],
    35: [34],
    36: [26, 37, 41],
    37: [36],
    38: [26, 39, 41],
    39: [26, 38],
    40: [26],
    41: [26, 34, 36, 38],
    42: [44],
    # 43: [],
    44: [42, 45],
    45: [44, 46],
    46: [45, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56],
    47: [46],
    48: [46],
    49: [46],
    50: [46],
    51: [46],
    52: [46],
    53: [46],
    54: [46],
    55: [46],
    56: [46]}

block_dict = {'ahnlab': ['1.A.4', '4.A.3', '10.A.1', '15.A.4', '18.A.4'], 'bitdefender': [], 'checkpoint': ['1.A.1', '6.A.1', '7.A.4', '9.A.5', '10.A.1', '15.A.4', '18.A.4'], 'cisco': ['1.A.1', '4.A.3', '7.A.3', '9.A.5', '10.A.1', '15.A.4', '18.A.4'], 'crowdstrike': ['1.A.2', '4.A.3', '7.A.3', '8.A.1', '9.A.3', '10.A.1', '11.A.3', '15.A.6', '18.A.4'], 'cybereason': ['1.A.1', '4.A.4', '7.A.3', '8.A.1', '9.A.1', '10.A.1', '11.A.3', '15.A.4', '19.A.1'], 'cycraft': ['1.A.1', '6.A.1', '10.A.1', '11.A.3'], 'cylance': ['1.A.7', '5.A.1', '7.A.4', '8.A.1', '9.A.2', '10.A.1', '12.A.3', '15.A.4', '18.A.4'], 'cynet': ['1.A.2', '4.A.3', '7.A.3', '8.A.1', '9.A.2', '10.A.1', '11.A.3', '15.A.3', '18.A.4'], 'deepinstinct': ['3.A.4', '6.A.1', '7.A.5', '8.A.1', '9.A.2', '10.A.1', '15.A.3', '18.A.4'], 'elastic': [], 'eset': ['1.A.3', '6.A.1', '15.A.4'], 'fidelis': [], 'fireeye': ['1.A.1', '6.A.1', '7.A.4', '10.A.1', '15.A.4', '18.A.4'], 'fortinet': ['1.A.3', '4.A.4', '7.A.3', '8.A.1', '9.A.5', '10.A.1', '15.A.6', '19.A.5'], 'malwarebytes': ['1.A.3', '4.A.4', '7.A.3', '8.A.1', '9.A.5', '10.A.1', '15.A.3', '18.A.4'], 'mcafee': ['1.A.1', '5.A.4', '9.A.5', '10.A.1', '15.A.3', '19.A.1'], 'microsoft': ['1.A.1', '4.A.3', '7.A.3', '8.A.2', '9.A.2', '10.A.1', '12.A.2', '15.A.3', '18.A.4'], 'paloaltonetworks': ['1.A.1', '4.A.3', '7.A.3', '8.A.1', '9.A.1', '10.A.1', '11.A.4', '15.A.3', '18.A.4'], 'qualys': [], 'rapid7': [], 'reaqta': [], 'sentinelone': ['1.A.1', '4.A.3', '7.A.3', '8.A.1', '9.A.1', '10.A.1', '11.A.3', '15.A.3', '18.A.4'], 'somma': [], 'sophos': ['1.A.4', '5.A.8', '15.A.4', '19.A.1'], 'symantec': ['1.A.4', '6.A.1', '7.A.3', '10.A.1', '13.A.1', '15.A.8'], 'trendmicro': ['1.A.3', '4.A.3', '7.A.3', '8.A.1', '9.A.1', '10.A.1', '15.A.3', '19.A.1'], 'uptycs': ['10.A.4'], 'vmware': ['1.A.4', '6.A.2', '7.A.4', '8.A.2', '9.A.5', '10.A.1', '15.A.6', '19.A.1'], 'withsecure': []}
wizard_spider_dict = {'1.A.1': 0, '1.A.2': 1, '1.A.3': 2, '1.A.4': 3, '1.A.5': 4, '1.A.6': 5, '1.A.7': 6, '1.A.8': 7, '1.A.9': 8, '1.A.10': 9, '1.A.11': 10, '2.A.1': 11, '3.A.1': 12, '3.A.2': 13, '3.A.3': 14, '3.A.4': 15, '3.A.5': 16, '4.A.1': 17, '4.A.2': 18, '4.A.3': 19, '4.A.4': 20, '4.A.5': 21, '5.A.1': 22, '5.A.2': 23, '5.A.3': 24, '5.A.4': 25, '5.A.5': 26, '5.A.6': 27, '5.A.7': 28, '5.A.8': 29, '5.A.9': 30, '6.A.1': 31, '6.A.2': 32, '7.A.1': 33, '7.A.2': 34, '7.A.3': 35, '7.A.4': 36, '7.A.5': 37, '8.A.1': 38, '8.A.2': 39, '9.A.1': 40, '9.A.2': 41, '9.A.3': 42, '9.A.4': 43, '9.A.5': 44, '10.A.1': 45, '10.A.2': 46, '10.A.3': 47, '10.A.4': 48, '10.A.5': 49, '10.A.6': 50, '10.A.7': 51}
sandworm_dict = {'11.A.1': 0, '11.A.2': 1, '11.A.3': 2, '11.A.4': 3, '12.A.1': 4, '12.A.2': 5, '12.A.3': 6, '12.A.4': 7, '12.A.5': 8, '13.A.1': 9, '13.A.2': 10, '13.A.3': 11, '13.A.4': 12, '13.A.5': 13, '14.A.1': 14, '14.A.2': 15, '14.A.3': 16, '14.A.4': 17, '14.A.5': 18, '15.A.1': 19, '15.A.2': 20, '15.A.3': 21, '15.A.4': 22, '15.A.5': 23, '15.A.6': 24, '15.A.7': 25, '15.A.8': 26, '15.A.9': 27, '15.A.10': 28, '16.A.1': 29, '16.A.2': 30, '16.A.3': 31, '16.A.4': 32, '16.A.5': 33, '17.A.1': 34, '17.A.2': 35, '17.A.3': 36, '17.A.4': 37, '17.A.5': 38, '17.A.6': 39, '17.A.7': 40, '17.A.8': 41, '18.A.1': 42, '18.A.2': 43, '18.A.3': 44, '18.A.4': 45, '19.A.1': 46, '19.A.2': 47, '19.A.3': 48, '19.A.4': 49, '19.A.5': 50, '19.A.6': 51, '19.A.7': 52, '19.A.8': 53, '19.A.9': 54, '19.A.10': 55, '19.A.11': 56}
sub_dict = {}

for vendor, block_lst in block_dict.items():
    if vendor not in sub_dict.keys():
        sub_dict[vendor] = {}
    for b in block_lst:
        if b in wizard_spider_dict.keys():
            if 'wizard_spider' not in sub_dict[vendor].keys():
                sub_dict[vendor]['wizard_spider'] = []
            idx = wizard_spider_dict[b]
            if idx < 17:
                sub_lst = [x for x in range(0, idx+1)]
            elif idx < 33:
                sub_lst = [x for x in range(17, idx+1)]
            else:
                sub_lst = [x for x in range(33, idx+1)]
            sub_dict[vendor]['wizard_spider'].append(sub_lst)
        elif b in sandworm_dict.keys():
            if 'sandworm' not in sub_dict[vendor].keys():
                sub_dict[vendor]['sandworm'] = []
            idx = sandworm_dict[b]
            if idx < 19:
                sub_lst = [x for x in range(0, idx+1)]
            elif idx < 42:
                sub_lst = [x for x in range(19, idx+1)]
            else:
                sub_lst = [x for x in range(42, idx+1)]
            sub_dict[vendor]['sandworm'].append(sub_lst)
        else:
            print('something weird happened')
            print(b)
# print(sub_dict)
freq_dict = {}
for vendor, eval_dict in sub_dict.items():
    for eval, sub_lst in eval_dict.items():
        if eval not in freq_dict.keys():
            freq_dict[eval] = {}
        for sub in sub_lst:
            if str(sub) not in freq_dict[eval].keys():
                freq_dict[eval][str(sub)] = 1
            else:
                freq_dict[eval][str(sub)] += 1
# print(freq_dict)
sorted_freq_dict = {}
for eval, eval_dict in freq_dict.items():
    sorted_freq_dict[eval] = {k: v for k, v in sorted(eval_dict.items(), key=lambda item: item[1])}
# sorted_freq_dict = {k: v for k, v in sorted(freq_dict.items(), key=lambda item: item[1])}
print(sorted_freq_dict)

# Create a graph
G_sandworm = nx.Graph()
G_wizard_spider = nx.Graph()

# Add nodes to the graph
# G.add_nodes_from(wizard_spider_connectivity.keys())
G_sandworm.add_nodes_from(sandworm_connectivity.keys())
G_wizard_spider.add_nodes_from(wizard_spider_connectivity.keys())

# Add edges to the graph based on the connectivity matrix
for node, neighbors in sandworm_connectivity.items():
    for neighbor in neighbors:
        G_sandworm.add_edge(node, neighbor)

for node, neighbors in wizard_spider_connectivity.items():
    for neighbor in neighbors:
        G_wizard_spider.add_edge(node, neighbor)

# Draw the graph
pos = graphviz_layout(G_sandworm, prog='dot')
nx.draw_networkx_nodes(G_sandworm, pos, node_size=20)
nx.draw_networkx_edges(G_sandworm, pos, width=1)
# nx.draw_networkx_nodes(G_wizard_spider.subgraph([0, 17, 33]), pos, node_color='red', node_size=20)
nx.draw_networkx_nodes(G_sandworm.subgraph([0, 19, 42]), pos, node_color='red', node_size=20)
# nx.draw_networkx_labels(G, pos, font_size=16, font_family="sans-serif")
# nx.draw(G, pos)


plt.axis("off")
plt.show()
