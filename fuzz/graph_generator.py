import networkx
import io

class GraphGenerator:

    def __init__(self) -> None:
        self._graph_type = []

    def gen(self, fdp, logging=False) -> networkx.graph:
        type_id = fdp.ConsumeIntInRange(0, len(self._graph_type) - 1)
        self._logging = logging
        if self._logging:
            print(self._graph_type[type_id])
        return self._graph_type[type_id](fdp)
    
    @property
    def name(self) -> str:
        return ''

class BasicGenerator(GraphGenerator):

    # Ref: OSS-fuzz implementation
    # https://github.com/google/oss-fuzz

    def __init__(self, n_max_byte) -> None:
        self._n_max_byte = n_max_byte
        self._graph_type = [self._graphml, self._graph6, self._sparse6]

    def _graphml(self, fdp) -> networkx.Graph:
        n_bytes = fdp.ConsumeIntInRange(1, self._n_max_byte)
        data = fdp.ConsumeBytes(n_bytes)
        return networkx.read_graphml(io.BytesIO(data))

        
    def _graph6(self, fdp) -> networkx.Graph:
        n_bytes = fdp.ConsumeIntInRange(5, self._n_max_byte)
        data = fdp.ConsumeBytes(n_bytes)
        if len(data) < 5:
            return networkx.Graph()
        return networkx.from_graph6_bytes(data)
        
    def _sparse6(self, fdp) -> networkx.Graph:
        n_bytes = fdp.ConsumeIntInRange(5, self._n_max_byte)
        data = fdp.ConsumeBytes(n_bytes)
        if len(data) < 5:
            return networkx.Graph()
        return networkx.from_sparse6_bytes(data)
    
    @property
    def name(self) -> str:
        return 'BasicGenerator'

class StructuralGenerator(GraphGenerator):

    def __init__(self, n_max_node, max_seed) -> None:
        self._graph_type = [self._fast_gnp_random_graph, self._gnp_random_graph, self._gnm_random_graph,
                            self._dense_gnm_random_graph, self._watts_strogatz_graph, self._newman_watts_strogatz_graph,
                            self._random_regular_graph, self._barabasi_albert_graph, self._powerlaw_cluster_graph,
                            self._random_lobster]
        self.N_MAX_NODE = n_max_node
        self.MAX_SEED = max_seed

    def _rand_n_node(self, fdp) -> int:
        val = fdp.ConsumeIntInRange(0, self.N_MAX_NODE)
        if self._logging:
            print('n_node =', val)
        return val
    
    def _rand_n_edge(self, fdp, n_node) -> int:
        n_max_edge = int(n_node * (n_node - 1) / 2)
        val = fdp.ConsumeIntInRange(0, n_max_edge)
        if self._logging:
            print('n_edge =', val)
        return val
    
    def _rand_n_neighbor(self, fdp, n_node) -> int:
        n_max_neighbor = n_node
        val = fdp.ConsumeIntInRange(0, n_max_neighbor)
        if self._logging:
            print('n_neighbor =', val)
        return val

    def _rand_prob(self, fdp) -> float:
        val = 0.5
        # Uncomment the next line to reproduce the ZeroDivisionError
        # val = fdp.ConsumeProbability() 
        if self._logging:
            print('prob =', val)
        return val
    
    def _rand_seed(self, fdp) -> int:
        val = fdp.ConsumeIntInRange(1, self.MAX_SEED)
        if self._logging:
            print('seed =', val)
        return val
    
    def _rand_directed(self, fdp) -> bool:
        val = fdp.ConsumeBool()
        if self._logging:
            print('directed =', val)
        return val
    
    def _fast_gnp_random_graph(self, fdp) -> networkx.Graph:
        n_node, prob, seed = self._rand_n_node(fdp), self._rand_prob(fdp), self._rand_seed(fdp)
        directed = self._rand_directed(fdp)
        return networkx.fast_gnp_random_graph(n=n_node, p=prob, seed=seed, directed=directed)

    def _gnp_random_graph(self, fdp) -> networkx.Graph:
        n_node, prob, seed = self._rand_n_node(fdp), self._rand_prob(fdp), self._rand_seed(fdp)
        directed = self._rand_directed(fdp)
        return networkx.gnp_random_graph(n=n_node, p=prob, seed=seed, directed=directed)
    
    def _gnm_random_graph(self, fdp) -> networkx.Graph:
        n_node, seed = self._rand_n_node(fdp), self._rand_seed(fdp)
        n_edge = self._rand_n_edge(fdp, n_node)
        directed = self._rand_directed(fdp)
        return networkx.gnm_random_graph(n=n_node, m=n_edge, seed=seed, directed=directed)

    def _dense_gnm_random_graph(self, fdp) -> networkx.Graph:
        n_node, seed = self._rand_n_node(fdp), self._rand_seed(fdp)
        n_edge = self._rand_n_edge(fdp, n_node)
        return networkx.dense_gnm_random_graph(n=n_node, m=n_edge, seed=seed)
    
    def _watts_strogatz_graph(self, fdp) -> networkx.Graph:
        n_node, prob, seed = self._rand_n_node(fdp), self._rand_prob(fdp), self._rand_seed(fdp)
        n_neighbor = self._rand_n_neighbor(fdp, n_node)
        return networkx.watts_strogatz_graph(n=n_node, k=n_neighbor, p=prob, seed=seed)
    
    def _newman_watts_strogatz_graph(self, fdp) -> networkx.Graph:
        n_node, prob, seed = self._rand_n_node(fdp), self._rand_prob(fdp), self._rand_seed(fdp)
        n_neighbor = self._rand_n_neighbor(fdp, n_node)
        return networkx.newman_watts_strogatz_graph(n=n_node, k=n_neighbor, p=prob, seed=seed)
    
    def _random_regular_graph(self, fdp) -> networkx.Graph:
        n_node, seed = self._rand_n_node(fdp), self._rand_seed(fdp)
        degree = self._rand_n_neighbor(fdp, n_node)
        return networkx.random_regular_graph(d=degree, n=n_node, seed=seed)

    def _barabasi_albert_graph(self, fdp) -> networkx.Graph:
        n_node, seed = self._rand_n_node(fdp), self._rand_seed(fdp)
        n_edge = self._rand_n_edge(fdp, n_node)
        return networkx.barabasi_albert_graph(n=n_node, m=n_edge, seed=seed)
    
    def _powerlaw_cluster_graph(self, fdp) -> networkx.Graph:
        n_node, prob, seed = self._rand_n_node(fdp), self._rand_prob(fdp), self._rand_seed(fdp)
        n_edge = self._rand_n_edge(fdp, n_node)
        return networkx.powerlaw_cluster_graph(n=n_node, m=n_edge, p=prob, seed=seed)
    
    def _random_lobster(self, fdp) -> networkx.graph:
        n_node, prob1, prob2, seed = self._rand_n_node(fdp), self._rand_prob(fdp), self._rand_prob(fdp), self._rand_seed(fdp)
        return networkx.random_lobster(n=n_node, p1=prob1, p2=prob2, seed=seed)
    
    @property
    def name(self) -> str:
        return 'StructuralGenerator'