import networkx
import math

class TestAlgorithm:

    def __init__(self) -> None:
        self._required_graph = 0

    def test(self, fdp, graphs: list) -> None:
        pass

    @property
    def required_graph(self) -> int:
        return self._required_graph
    
    @property
    def name(self) -> str:
        return ''

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
        # print(graph.nodes)
        # print(graph.adj)
        assert dijstra_len == bellman_ford_len

    @property
    def name(self) -> str:
        return 'TestShortestPath'

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

        # Uncomment the next two lines to reproduce max-flow inconsistency
        # assert edmonds_karp.graph['flow_value'] == shortest_augmenting_path.graph['flow_value'] == preflow_push.graph['flow_value'] \
        #     == dinitz.graph['flow_value'] == boykov_kolmogorov.graph['flow_value']

        if  not (math.isclose(edmonds_karp.graph['flow_value'], shortest_augmenting_path.graph['flow_value']) and
                math.isclose(edmonds_karp.graph['flow_value'], preflow_push.graph['flow_value']) and 
                math.isclose(edmonds_karp.graph['flow_value'], dinitz.graph['flow_value']) and
                math.isclose(edmonds_karp.graph['flow_value'], boykov_kolmogorov.graph['flow_value'])):
            assert False
        
    @property
    def name(self) -> str:
        return 'TestMaxFlow'

class TestIsomorphic(TestAlgorithm):


    def __init__(self) -> None:
        self._required_graph = 2

    def test(self, fdp, graphs: list) -> None:

        g1: networkx.Graph
        g2: networkx.Graph

        g1, g2 = graphs

        # Comment the next if statement to reproduce vf2/vf2pp inconsistency on null graph
        # if (len(g1.nodes) == 0 and len(g1.edges) == 0 and \
        #           len(g2.nodes) == 0 and len(g2.edges) == 0  ):
        #     return

        vf2 = networkx.is_isomorphic(g1, g2)
        vf2pp = networkx.vf2pp_is_isomorphic(g1, g2)
        print(g1, 'and', g2)
        print('vf2 result:', vf2)
        print('vf2pp result:', vf2pp)

        assert vf2 == vf2pp

        mapping = {node: fdp.ConsumeRegularFloat() for node in g1.nodes}
        g1_relabel = networkx.relabel_nodes(g1, mapping=mapping)

        if len(g1_relabel.nodes) != len(g1.nodes): # mapping might cause multiple nodes to merge into one
            return
        if len(g1.nodes) == 0:
            return

        assert networkx.is_isomorphic(g1, g1_relabel)
        assert networkx.vf2pp_is_isomorphic(g1, g1_relabel)

    @property
    def name(self) -> str:
        return 'TestIsomorphic'