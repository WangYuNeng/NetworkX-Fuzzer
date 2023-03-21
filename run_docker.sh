#!/bin/bash
docker build -t cs295-final . && \
	docker run -it --entrypoint /bin/bash -v "${PWD}/fuzz:/home/NetworkX-Fuzzer/fuzz:z" cs295-final
