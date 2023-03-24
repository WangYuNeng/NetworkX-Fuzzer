import networkx

class TestAlgorithm:

    def __init__(self) -> None:
        self._required_graph = 0

    def test(self, fdp, graphs: list) -> None:
        pass

    @property
    def required_graph(self) -> int:
        return self._required_graph

def assign_rand_weight(fdp, graph: networkx.Graph, non_negative=True):
    max = 1
    if non_negative == True:
        min = 0
    else:
        min = -max
    for e in graph.edges:
        graph.edges[e]['weight'] = fdp.ConsumeFloatInRange(min, max)

class TestShortestPath(TestAlgorithm):

    def __init__(self) -> None:
        self._required_graph = 1

    def test(self, fdp, graphs) -> None:
        graph = graphs[0]
        assign_rand_weight(fdp, graph, non_negative=True)
        dijstra_len = dict(networkx.all_pairs_dijkstra_path_length(graph))
        bellman_ford_len = dict(networkx.all_pairs_bellman_ford_path_length(graph))
        # johnson_len = networkx.johnson(graph)
        # floyd_warshall_len = networkx.floyd_warshall(graph)
        assert dijstra_len == bellman_ford_len # == johnson_len == floyd_warshall_len

    # def _transform_fw(fw_len: dict):
        
    #     new_fw_len = {}
    #     for node in fw_len

class TestMaxFlow(TestAlgorithm):

    def __init__(self) -> None:
        self._required_graph = 1

    def test(self, fdp, graphs: list) -> None:
        graph = graphs[0]
        assign_rand_weight(fdp, graph, non_negative=True)
        node_list = list(graph.nodes)
        if node_list == []:
            return
        src, dst = fdp.PickValueInList(node_list), fdp.PickValueInList(node_list)
        edmonds_karp = networkx.flow.edmonds_karp(graph, src, dst, capacity='weight')
        shortest_augmenting_path = networkx.flow.shortest_augmenting_path(graph, src, dst, capacity='weight')
        preflow_push = networkx.flow.preflow_push(graph, src, dst, capacity='weight')
        dinitz = networkx.flow.dinitz(graph, src, dst, capacity='weight')
        boykov_kolmogorov = networkx.flow.boykov_kolmogorov(graph, src, dst, capacity='weight')
        if not edmonds_karp.graph['flow_value'] == shortest_augmenting_path.graph['flow_value'] == preflow_push.graph['flow_value'] \
            == dinitz.graph['flow_value'] == boykov_kolmogorov.graph['flow_value']:
            print(graph.nodes, graph.edges, src, dst)
            print(edmonds_karp.graph['flow_value'], shortest_augmenting_path.graph['flow_value'], preflow_push.graph['flow_value'], dinitz.graph['flow_value'], boykov_kolmogorov.graph['flow_value'])
            assert False
        

# class TestIsomorphic(TestAlgorithm):


