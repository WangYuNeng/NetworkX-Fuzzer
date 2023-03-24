# Ref: OSS-fuzz implementation
# https://github.com/google/oss-fuzz

import sys
import atheris
import xml


with atheris.instrument_imports():
    from graph_generator import BasicGenerator, StructuralGenerator
    import networkx
    # generator = BasicGenerator(n_max_byte=400)
    generator = StructuralGenerator(n_max_node=5, max_seed=428)

CATCHED_EXCEPTION = (ZeroDivisionError, ValueError, networkx.NetworkXError, xml.etree.ElementTree.ParseError, LookupError)

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        generator.gen(fdp=fdp)
    except CATCHED_EXCEPTION:
        pass


def main():
    # atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()