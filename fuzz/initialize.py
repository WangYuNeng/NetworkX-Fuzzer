import argparse

from graph_generator import StructuralGenerator, BasicGenerator
from algorithm import TestShortestPath, TestMaxFlow, TestIsomorphic


class  FuzzInitializer:

    def __init__(self) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument('-g', '--generator', help='select graph generator (0: basic, 1: structural, 2: both)', type=int, choices=[0, 1, 2])
        parser.add_argument('-sp', '--shortest-path', help='fuzz shortest path algorithms', action='store_true')
        parser.add_argument('-mf', '--max-flow', help='fuzz max flow algorithms', action='store_true')
        parser.add_argument('-iso', '--isomorphism', help='fuzz isomorphism algorithms', action='store_true')
        parser.add_argument('-l', '--logging', help='log exception information to file', type=str, default='tmp')
        parser.add_argument('-n', '--runs', help='times to run', type=int, default=50000)
        self._parser = parser

    def parse(self):
        self._args = self._parser.parse_args()

    def initialize(self):
        args = self.args

        generators = []
        if args.generator == 0:
            generators = [BasicGenerator(n_max_byte=100)]
        elif args.generator == 1:
            generators = [StructuralGenerator(n_max_node=20, max_seed=428)]
        elif args.generator == 2:
            generators = [BasicGenerator(n_max_byte=100), StructuralGenerator(n_max_node=20, max_seed=428)]
        
        algorithms = []
        if args.shortest_path:
            algorithms.append(TestShortestPath())
        if args.max_flow:
            algorithms.append(TestMaxFlow())
        if args.isomorphism:
            algorithms.append(TestIsomorphic())

        return generators, algorithms

    @property
    def args(self):
        return self._args