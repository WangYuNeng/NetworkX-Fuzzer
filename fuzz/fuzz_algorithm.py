
import sys
import atheris
import xml

with atheris.instrument_imports():
    from graph_generator import StructuralGenerator, BasicGenerator
    from algorithm import TestShortestPath, TestMaxFlow
    import networkx
    # generator = BasicGenerator(n_max_byte=100)
    generator = StructuralGenerator(n_max_node=20, max_seed=428)
    sp = TestShortestPath()
    flow = TestMaxFlow()

GENERATOR_EXCEPTION = (ZeroDivisionError, ValueError, networkx.NetworkXError, xml.etree.ElementTree.ParseError, LookupError)
ALGORITHM_EXCEPTION = (networkx.NetworkXError, networkx.NetworkXUnbounded)

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        g = generator.gen(fdp=fdp)
    except GENERATOR_EXCEPTION:
        return

    try:
        flow.test(fdp, [g])
    except ALGORITHM_EXCEPTION:
        pass

    # try:
    #     sp.test(fdp, [g])
    # except ALGORITHM_EXCEPTION:
    #     pass



def main():
    # atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()