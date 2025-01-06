"""
    Script que realiza un escaneo de una red dada y obtiene las direcciones
    MAC de los dispositivos.
    Tienes que correr este script como root o usando "sudo" para obtener las direcciones
    Mac."""

import subprocess
import argparse
parser = argparse.ArgumentParser(description='Realiza un escaneo dada una red.')
parser.add_argument('network', metavar='NETWORK', type=str, help='La red a escanear')

try:
    import nmap
except ImportError:
    print("Instalando dependencias necesarias...")
    try:
        subprocess.check_call(['pip','install','python-nmap'])
        print("Librería nmap instalada correctamente")
    except subprocess.CalledProcessError:
        print("Error al instalar la librería python-nmap")

def escaneo_red(network):
    """"
    Se hace un escaneo dada una red y se obtiene la información de los dispositivos
    activos en la red, para después retornarlos como un diccionario.
    """
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network, arguments='-sS --min-rate 5000')   # Escaneo de puertos
        upDevices = {}
        ports = {}
        protocols = []
        for host in nm.all_hosts():
            state = nm[host].state()
            if state == 'up':
                upDevices[host] = nm[host] # Se almacena toda información del host
                protocols = nm[host].all_protocols()
                for protocol in protocols:
                    ports[host] = list(nm[host][protocol].keys())   # Puertos abiertos de un host individual
            else:
                continue
        return upDevices, ports
    except Exception as e:
        print(f"Error al escanear la red. Inténtelo de nuevo. {e}")
        return {},{}
    

def obtener_mac_address(upDevices):
    """"
    Dado un diccionario de dispositivos, se obtiene la dirección MAC de cada uno de ellos.
    Y se retorna un diccionario con la dirección MAC de cada host.
    """
    mac_address = {}
    for ip, host_data in upDevices.items():
        try:
            if 'mac' in host_data['addresses']:
                mac_address[ip] = host_data['addresses']['mac']
            else: 
                mac_address[ip] = "No se pudo obtener la dirección MAC..."
        except KeyError:
            mac_address[ip] = "Información insuficiente..."
    return mac_address

if __name__ == '__main__':
    args = parser.parse_args()
    network = args.network
    upDevices, ports = escaneo_red(network)

    if upDevices:
        mac_address = obtener_mac_address(upDevices)
        print("Dispositivos encontrados en la red: \n")
        for ip, mac in mac_address.items():
            print(f"IP: {ip} - MAC: {mac}")
            if ports[ip]:
                print("Este dispositivo tiene los siguientes puertos abiertos: ")
                print(ports[ip])
    else:
        print("No se encontraron dispositivos en la red...")