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
        total_hosts = nm.scan(hosts=network, arguments='-sL')
        upDevices = {}
        for host in total_hosts['scan']:
            if total_hosts['scan'][host]['status']['state'] != 'down':
                upDevices[host] = total_hosts['scan'][host]
            else:
                continue
        return upDevices
    except Exception as e:
        print(f"Error al escanear la red. Inténtelo de nuevo. {e}")
        return{}

def obtener_mac_address(upDevices):
    mac_address = {}
    for ip in upDevices:
        if 'mac' in upDevices[ip]['addresses']:
            mac_address[ip] = upDevices[ip]['addresses']['mac']
        else:
            mac_address[ip] = "No se pudo obtener la dirección MAC..."
    return mac_address

if __name__ == '__main__':
    args = parser.parse_args()
    network = args.network
    upDevices = escaneo_red(network)

    if upDevices:
        mac_address = obtener_mac_address(upDevices)
        for ip, mac in mac_address.items():
            print(f"IP: {ip} - MAC: {mac}")
    else:
        print("No se encontraron dispositivos en la red...")