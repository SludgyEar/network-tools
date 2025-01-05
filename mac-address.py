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
    nmap = nmap.PortScanner()
    result = nmap.scan(hosts=network, arguments='-sL')
    return result

def show_devices(result):
    for host in result['scan']:
        print(f"Host: {host}, Estado {result['scan'][host]['status']['state']}")


if __name__ == '__main__':
    args = parser.parse_args()
    network = args.network
    show_devices(escaneo_red(network))