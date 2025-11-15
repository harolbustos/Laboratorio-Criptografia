FROM ubuntu:16.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y openssh-client iproute2 iputils-ping tcpdump ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# mantener el contenedor en ejecucion
CMD ["tail", "-f", "/dev/null"]
