FROM ubuntu:22.04
RUN apt update
RUN apt --fix-missing -y install git python3-pip
RUN pip3 install atheris==2.2.2 networkx==3.0
RUN mkdir -p /home/NetworkX-Fuzzer
WORKDIR /home/NetworkX-Fuzzer
COPY fuzz fuzz
