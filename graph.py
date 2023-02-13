class Graph:
    def __init__(self):
        self.adj_list = {}

    def add_node(self, node):
        if node not in self.adj_list:
            self.adj_list[node] = []

    def add_edge(self, node1, node2):
        self.adj_list[node1].append(node2)
        self.adj_list[node2].append(node1)

    def remove_node(self, node):
        if node in self.adj_list:
            del self.adj_list[node]
        for key in self.adj_list:
            if node in self.adj_list[key]:
                self.adj_list[key].remove(node)

    def connected_components(self):
        visited = set()
        components = []

        def dfs(node, component):
            visited.add(node)
            component.append(node)
            for neighbor in self.adj_list.get(node, []):
                if neighbor not in visited:
                    dfs(neighbor, component)

        for node in self.adj_list:
            if node not in visited:
                component = []
                dfs(node, component)
                components.append(component)

        return components