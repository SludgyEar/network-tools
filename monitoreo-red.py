import subprocess
import argparse
parser = argparse.ArgumentParser(description='Realiza un escaneo dada una red. Debes de ejecutar este script como root o usando "sudo".')
parser.add_argument('network', metavar='NETWORK', type=str, help='Ingresa la red a escanear')

# python tu_script.py > salida.log 2>&1

try:
    from scapy.all import sniff, ARP, Ether, srp, send, conf
except ImportError:
    print("Instalando dependencias necesarias...")
    try:
        subprocess.check_call(['pip','install','scapy'])
        print("Librería Scapy instalada correctamente")
    except subprocess.CalledProcessError:
        print("Error al instalar dependencias necesarias...")

def escaneo_red(network):
    try:
        arp = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp
        result = srp(packet, timeout=2, verbose=False)[0]
        upDevices = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]
        return upDevices
    except Exception as e:
        print(f"Error al escanear la red: {e}")
        return []

# def arp_spoof(upDevices):     # Fckd up my device for a while, i'll try to use it in a private network running tru VM's
#     gateway = conf.route.route("0.0.0.0")[2]    # Gateway IP
#     for device in upDevices:
#         packet = ARP(op=2, pdst=device['ip'], hwdst=device['mac'], psrc=gateway)
#         send(packet)

def capturar_paquetes(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        print(f"ARP packet: {packet.summary()}")

def monitoreo_red(upDevices):
    for _ in range(100):
        # arp_spoof(upDevices)
        sniff(iface="eth0", prn=capturar_paquetes, count=10)

if __name__ == '__main__':
    args = parser.parse_args()
    network = args.network
    upDevices = escaneo_red(network)

    if upDevices:
        print("Dispositivos activos en la red:")
        for device in upDevices:
            print(f"IP: {device['ip']} MAC: {device['mac']}")
        input("Iniciando con la captura de paquetes. Presiona Enter para continuar...")
        # monitoreo_red(upDevices)
    else:
        print("No se encontraron dispositivos activos en la red.")