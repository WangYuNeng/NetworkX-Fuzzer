
import sys
import argparse
import atheris
import xml

with atheris.instrument_imports():
    from initialize import FuzzInitializer
    import networkx

    init = FuzzInitializer()
    init.parse()
    generators, algorithms = init.initialize()
    log_file = open(init.args.logging, 'w')
    log_file.write('python3 {}\n'.format(' '.join(sys.argv)))

GENERATOR_EXCEPTION = (ValueError, networkx.NetworkXError, xml.etree.ElementTree.ParseError, LookupError)
ALGORITHM_EXCEPTION = (networkx.NetworkXError, networkx.NetworkXUnbounded)

def TestOneInput(data):

    
    fdp = atheris.FuzzedDataProvider(data)

    if algorithms == []:
        try:
            generator = fdp.PickValueInList(generators)
            graphs = generator.gen(fdp=fdp)
        except GENERATOR_EXCEPTION as e:
            log_file.write('Failed at {}: {}\n'.format(generator.name, str(e)))
            return
        
        log_file.write('Pass\n')
        return
    
    algo = fdp.PickValueInList(algorithms)

    try:
        generator_choices = [fdp.PickValueInList(generators) for _ in range(algo.required_graph)]
        graphs = [g.gen(fdp=fdp) for g in generator_choices]
    except GENERATOR_EXCEPTION as e:
        log_file.write('Failed at {}: {}\n'.format([g.name for g in generator_choices], str(e)))
        return

    try:
        algo.test(fdp=fdp, graphs=graphs)
    except ALGORITHM_EXCEPTION as e:
        log_file.write('Failed at {}: {}\n'.format(algo.name, str(e)))
        return

    log_file.write('Pass\n')


def main():
    # atheris.instrument_all()
    atheris.Setup(['fuzzer.py', '-atheris_runs={}'.format(init.args.runs)], TestOneInput, enable_python_coverage=True)
    # atheris.Setup(['fuzzer.py', '-help=1'], TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()