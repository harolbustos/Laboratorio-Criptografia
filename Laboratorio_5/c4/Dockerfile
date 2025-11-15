FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y openssh-server openssh-client passwd iproute2 iputils-ping tcpdump ca-certificates && \
    mkdir -p /var/run/sshd && \
    # crear usuario prueba con contraseña 'prueba'
    useradd -m -s /bin/bash prueba && echo "prueba:prueba" | chpasswd && \
    # permitir password authentication
    sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config || true && \
    sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config || true && \
    # generar host keys
    ssh-keygen -A && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# exponer puerto 22
EXPOSE 22

# ejecutar sshd en foreground
CMD ["/usr/sbin/sshd", "-D"]
