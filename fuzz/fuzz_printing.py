import os
import atheris
from graph_generator import BasicGenerator, StructuralGenerator

generator = StructuralGenerator(n_max_node=5, max_seed=428)

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
                            generator.gen(fdp, logging=True)
#run_fuzzer()
report_fuzzer_inputs()
