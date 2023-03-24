import os
import atheris
import xml
import networkx
from graph_generator import BasicGenerator, StructuralGenerator
from algorithm import TestShortestPath, TestMaxFlow

generator = StructuralGenerator(n_max_node=5, max_seed=428)
sp = TestShortestPath()
flow = TestMaxFlow()

GENERATOR_EXCEPTION = (ZeroDivisionError, ValueError, networkx.NetworkXError, xml.etree.ElementTree.ParseError, LookupError)
ALGORITHM_EXCEPTION = (networkx.NetworkXError, networkx.NetworkXUnbounded)

def report_fuzzer_inputs():
        for root,dirs,files in os.walk(".",topdown=False):
                for filename in files:
                        if not "crash-" in filename and \
                           not "oom-" in filename and \
                           not "slow-unit" in filename:
                                continue

                        filepath = "%s/%s" % (root,filename)
                        with open(filepath, "rb") as fh:
                                print("file: %s" % filepath)
                                bytestr = fh.read()
                                print("bytes: <%s>" % bytestr)
                                fdp = atheris.FuzzedDataProvider(bytestr)
                                try:
                                        g = generator.gen(fdp, logging=True)
                                except GENERATOR_EXCEPTION:
                                        continue
                                try:
                                        flow.test(fdp, [g])
                                except ALGORITHM_EXCEPTION:
                                        pass

                                # try:
                                #         sp.test(fdp, [g])
                                # except ALGORITHM_EXCEPTION:
                                #         pass

                                print(list(g.nodes))
#run_fuzzer()
report_fuzzer_inputs()
