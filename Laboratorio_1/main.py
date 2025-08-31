## Partes 2.1 y 2.2 de la Actividad
from scapy.all import IP, ICMP, send
import time

## 2.1 Algoritmo de cifrado. Se usa el crifrado Cesar.
## Para ello se pide una palabra a cifrar y un numero entero.
def cifrado_cesar(texto, corrimiento):
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():  # Solo cifrar letras
            base = ord('A') if caracter.isupper() else ord('a')
            resultado += chr((ord(caracter) - base + corrimiento) % 26 + base)
        else:
            resultado += caracter
    return resultado

## 2.2 Enviar el mensaje ya cifrado en caracteres en varios paquetes ICMP
def enviar_icmp_caracteres(texto, destino="google.cl"):
    for caracter in texto:
        payload = caracter.encode() + b'X' * (48 - 1)

        paquete = IP(dst=destino) / ICMP(type=8) / payload
        send(paquete, verbose=False)

        print(f"Enviado caracter: {caracter}")
        time.sleep(0.5)  # delay


# Programa principal
if __name__ == "__main__":
    texto = input("Ingrese el texto a cifrar: ")
    corrimiento = int(input("Ingrese el corrimiento (número entero): "))

    texto_cifrado = cifrado_cesar(texto, corrimiento)
    print(f"\nTexto original: {texto}")
    print(f"Texto cifrado:  {texto_cifrado}")
    enviar_icmp_caracteres(texto_cifrado)

