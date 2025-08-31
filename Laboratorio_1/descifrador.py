from scapy.all import rdpcap, ICMP
import string

## Parte 2.3 MitM de la actividad.
# Extraer los caracteres de la captura de wireshark para descifrar el mensaje original.
def extraer_caracteres(pcap_file):

    paquetes = rdpcap(pcap_file)
    caracteres = []

    for pkt in paquetes:
        if ICMP in pkt and pkt[ICMP].payload:
            data = bytes(pkt[ICMP].payload.load)
            if len(data) == 48:
                caracter = chr(data[0])
                caracteres.append(caracter)

    # eliminar duplicados
    caracteres_unicos = []
    for i, c in enumerate(caracteres):
        if i % 2 == 0:
            caracteres_unicos.append(c)

    return "".join(caracteres_unicos)


def descifrar_cesar(texto, corrimiento):
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():
            base = ord('A') if caracter.isupper() else ord('a')
            resultado += chr((ord(caracter) - base - corrimiento) % 26 + base)
        else:
            resultado += caracter
    return resultado


if __name__ == "__main__":
    archivo = "mensaje.pcapng" # captura de wireshark
    mensaje_cifrado = extraer_caracteres(archivo)

    print(f"Texto cifrado obtenido: {mensaje_cifrado}\n")

    # Probar todos los corrimientos de 0 a 25
    for corr in range(26):
        posible = descifrar_cesar(mensaje_cifrado, corr)
        print(f"{corr:2d}:   {posible}")
