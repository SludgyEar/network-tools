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
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network, arguments='-sP')   # Ping Scan
        upDevices = {}
        for host in nm.all_hosts():
            state = nm[host].state()
            if state == 'up':
                upDevices[host] = nm[host] # Se almacena toda información del host
            else:
                continue
        return upDevices
    except Exception as e:
        print(f"Error al escanear la red. Inténtelo de nuevo. {e}")
        return{}

def obtener_mac_address(upDevices):
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
    upDevices = escaneo_red(network)

    if upDevices:
        mac_address = obtener_mac_address(upDevices)
        print("Dispositivos encontrados en la red: \n")
        for ip, mac in mac_address.items():
            print(f"IP: {ip} - MAC: {mac}")
    else:
        print("No se encontraron dispositivos en la red...")