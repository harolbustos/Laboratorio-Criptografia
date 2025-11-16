FROM ubuntu:20.04

# instala cliente SSH y herramientas de red
RUN apt-get update && apt-get install -y \
    openssh-client \
    tcpdump \
    iproute2 \
    procps \
    && rm -rf /var/lib/apt/lists/*

# mantiene el contenedor vivo
CMD ["sleep", "infinity"]