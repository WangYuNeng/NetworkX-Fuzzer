import os
import atheris
import xml
import networkx

from initialize import FuzzInitializer

init = FuzzInitializer()
init.parse()
generators, algorithms = init.initialize()

GENERATOR_EXCEPTION = (ValueError, networkx.NetworkXError, xml.etree.ElementTree.ParseError, LookupError)
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

                                if algorithms == []:
                                        try:
                                                generator = fdp.PickValueInList(generators)
                                                graphs = generator.gen(fdp=fdp)
                                        except GENERATOR_EXCEPTION as e:
                                                return
                                        
                                        return

                                algo = fdp.PickValueInList(algorithms)
                                try:
                                        gs = [fdp.PickValueInList(generators).gen(fdp=fdp) for _ in range(algo.required_graph)]
                                except GENERATOR_EXCEPTION:
                                        return

                                try:
                                        algo.test(fdp=fdp, graphs=gs)
                                except ALGORITHM_EXCEPTION:
                                        pass


#run_fuzzer()
report_fuzzer_inputs()
