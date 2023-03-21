import atheris

with atheris.instrument_imports():
    from networkx.generators import fast_gnp_random_graph
    import sys

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    n_node = fdp.ConsumeIntInRange(1, 10)
    prob = fdp.ConsumeProbability()
    if prob < 1e-6:
        return
    seed = fdp.ConsumeIntInRange(1, 1000)
    # print(n_node, prob, seed)
    fast_gnp_random_graph(n=n_node, p=prob, seed=seed)

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()