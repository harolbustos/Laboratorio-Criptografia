FROM ubuntu:22.04

# instala cliente, servidor y herramientas
RUN apt-get update && apt-get install -y \
    openssh-client \
    openssh-server \
    tcpdump \
    iproute2 \
    procps \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# crea el usuario "prueba" con home, shell y contraseña "prueba"
RUN useradd -m -s /bin/bash prueba && \
    echo "prueba:prueba" | chpasswd && \
    adduser prueba sudo

# configura el servidor SSH
RUN mkdir /var/run/sshd
# permite la autenticación con contraseña
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
RUN sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config

EXPOSE 22

# ejecuta el servidor SSH en primer plano
CMD ["/usr/sbin/sshd", "-D"]