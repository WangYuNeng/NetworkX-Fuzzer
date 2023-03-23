# Ref: OSS-fuzz implementation
# https://github.com/google/oss-fuzz

import sys
import atheris
import networkx
import xml
from graph_generator import BasicGenerator, StructuralGenerator

generator = BasicGenerator(n_max_byte=400)
# generator = StructuralGenerator(n_max_node=5, max_seed=428)

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        generator.gen(fdp=fdp)
    except ZeroDivisionError:
        pass
    except ValueError:
        pass
    except networkx.NetworkXError:
        pass
    except xml.etree.ElementTree.ParseError:
        pass
    except LookupError:
        pass


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()