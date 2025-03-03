#!/usr/bin/env python3

import argparse
import ipaddress
import json
import logging
import logging.handlers
import os
import re
import sys
from typing import Set, Dict, List, Any
import multiprocessing
import nmap
import urllib.request

# Valores por defecto
DEFAULT_LOG_FILE = '/var/log/nac/nac.log'
DEFAULT_IP_MAC_REGISTRY = 'ip_mac_registry.txt'
DEFAULT_CONN_LOG_PATH = '/opt/zeek/logs/current/conn.log'

###############################################################################
# Configuración de Logging y Argumentos
###############################################################################
def configurar_logging(log_server: str = None, debug: bool = False, log_type: str = 'syslog'):
    level = logging.DEBUG if debug else logging.INFO
    if log_type == 'syslog':
        fmt = '%(asctime)s||%(levelname)s||%(message)s'
    else:  # json
        fmt = '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s"}'
    logging.basicConfig(level=level, format=fmt)
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            DEFAULT_LOG_FILE, maxBytes=5*1024*1024, backupCount=5
        )
        file_handler.setFormatter(logging.Formatter(fmt))
        logging.getLogger().addHandler(file_handler)
    except Exception as e:
        logging.error(f"No se pudo configurar el archivo de log: {e}")
    if log_server:
        try:
            syslog_handler = logging.handlers.SysLogHandler(address=(log_server, 514))
            syslog_handler.setFormatter(logging.Formatter(fmt))
            logging.getLogger().addHandler(syslog_handler)
        except Exception as e:
            logging.error(f"No se pudo conectar al servidor Syslog {log_server}: {e}")

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="LAN Radar - Escaneo sin vulnerabilidades y catalogación de dispositivos"
    )
    parser.add_argument('--log_server', help='Servidor de logs remoto (Syslog)', default=None)
    parser.add_argument('--zeek_log', help='Ruta al log conn.log de Zeek', default=DEFAULT_CONN_LOG_PATH)
    parser.add_argument('--registry', help='Archivo de registro IP-MAC', default=DEFAULT_IP_MAC_REGISTRY)
    parser.add_argument('--nmap_options', help='Opciones adicionales para nmap', default=None)
    parser.add_argument('--log-type', choices=['syslog', 'json'], default='syslog', help='Tipo de log: syslog o json')
    parser.add_argument('--public_ip', action='store_true', help='Mostrar la IP pública del equipo y salir')
    parser.add_argument('--debug', action='store_true', help='Activar modo debug')
    return parser.parse_args()

###############################################################################
# Funciones para obtener la IP pública
###############################################################################
def obtener_ip_publica() -> str:
    try:
        with urllib.request.urlopen('https://ifconfig.me') as response:
            public_ip = response.read().decode('utf-8').strip()
            return public_ip
    except Exception as e:
        logging.error(f"Error obteniendo IP pública: {e}")
        return "Desconocida"

###############################################################################
# Funciones para filtrar y leer IPs de Zeek
###############################################################################
def es_ip_privada_y_no_multicast_broadcast(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if not ip_obj.is_private:
            return False
        if ip_obj.is_multicast:
            return False
        if ip_obj == ipaddress.ip_address("255.255.255.255"):
            return False
        if ip_obj == ipaddress.ip_address("0.0.0.0"):
            return False
        if ip_str.endswith(".255"):
            return False
        return True
    except ValueError:
        return False

def obtener_ips_de_zeek_connlog(conn_log_path: str) -> Set[str]:
    ips = set()
    if not os.path.exists(conn_log_path):
        logging.warning(f"No se encontró el archivo de Zeek: {conn_log_path}")
        return ips
    try:
        with open(conn_log_path, 'r') as f:
            for line in f:
                if line.startswith("#"):
                    continue
                campos = line.strip().split()
                if len(campos) < 5:
                    continue
                ip1, ip2 = campos[2], campos[4]
                for candidate in (ip1, ip2):
                    if re.match(r'^\d+\.\d+\.\d+\.\d+$', candidate):
                        ips.add(candidate)
    except Exception as e:
        logging.error(f"Error leyendo el archivo de Zeek: {e}")
    return ips

###############################################################################
# Funciones de registro IP-MAC
###############################################################################
def leer_ip_mac_registry(registry_path: str) -> Dict[str, str]:
    registros = {}
    if not os.path.exists(registry_path):
        return registros
    try:
        with open(registry_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split()
                    if len(parts) == 2:
                        ip, mac = parts
                        registros[ip] = mac
    except Exception as e:
        logging.error(f"Error leyendo el registro IP-MAC: {e}")
    return registros

def actualizar_ip_mac_registry(registry_path: str, ip: str, mac: str):
    registros = leer_ip_mac_registry(registry_path)
    registros[ip] = mac
    try:
        with open(registry_path, 'w') as f:
            for ip_key, mac_val in registros.items():
                f.write(f"{ip_key} {mac_val}\n")
    except Exception as e:
        logging.error(f"Error actualizando el registro IP-MAC: {e}")

###############################################################################
# Función para obtener las MAC reales usando nmap -sn
###############################################################################
def obtener_mac_todas_las_ips(nm: nmap.PortScanner, ips: List[str]) -> Dict[str, str]:
    ip_string = " ".join(ips)
    argumentos = '-sn'
    mac_map = {}
    try:
        nm.scan(hosts=ip_string, arguments=argumentos)
        for host in nm.all_hosts():
            mac = nm[host]['addresses'].get('mac')
            if mac:
                mac_map[host] = mac.upper()
    except Exception as e:
        logging.error(f"Error al obtener MAC en bloque: {e}")
    return mac_map

###############################################################################
# Escaneo rápido para detectar puertos abiertos
###############################################################################
def quick_scan(ip: str) -> List[int]:
    """
    Realiza un escaneo rápido en la IP utilizando:
      - Escaneo de todo el rango de puertos (-p-)
      - Timing optimizado (-T4) y sin reintentos (--max-retries 0)
    Retorna una lista ordenada de puertos abiertos.
    """
    argumentos = '-sS -p- --open --min-rate 5000 -n -Pn --max-retries 0'
    nm = nmap.PortScanner()
    open_ports = []
    try:
        nm.scan(hosts=ip, arguments=argumentos)
        if ip not in nm.all_hosts():
            return open_ports
        for proto in nm[ip].all_protocols():
            for port, info in nm[ip][proto].items():
                if info.get('state') == 'open':
                    open_ports.append(port)
    except Exception as e:
        logging.error(f"Error en quick_scan para {ip}: {e}")
    return sorted(set(open_ports))

###############################################################################
# Escaneo detallado sobre los puertos abiertos con información de vulnerabilidades
###############################################################################
def escaneo_detallado(ip: str, open_ports: List[int], nmap_options: str = None) -> dict:
    """
    Realiza un escaneo detallado en la IP sobre los puertos abiertos detectados:
      - Detección de versión (-sV) con intensidad alta
      - Especificación de puertos (-p)
      - Detección de OS (-O)
      - Ejecución de scripts por defecto y de vulnerabilidades (--script=default,vuln)
      - Timing optimizado (-T4) y sin reintentos (--max-retries 0)
    Retorna un diccionario con hostname, OS y detalle de servicios.
    Cada servicio incluirá, de existir, dos campos:
       • vuln_results: Resultados de vulnerabilidades detectadas.
       • vuln_errors: Mensajes de error en la ejecución de scripts.
    """
    if not open_ports:
        logging.info(f"No se detectaron puertos abiertos en {ip}. Se omite el escaneo detallado.")
        return {
            'ip': ip,
            'hostname': 'unknown',
            'os_info': 'Desconocido',
            'os_accuracy': None,
            'services': []
        }
    port_list = ",".join(str(port) for port in open_ports)
    argumentos_base = f'-sV --open --version-intensity 9 -p {port_list} -O --min-rate 5000 --max-retries 0'
    argumentos = f"{argumentos_base} {nmap_options}" if nmap_options else argumentos_base
    nm = nmap.PortScanner()
    resultado = {
        'ip': ip,
        'hostname': 'unknown',
        'os_info': 'Desconocido',
        'os_accuracy': None,
        'services': []
    }
    try:
        nm.scan(hosts=ip, arguments=argumentos)
        if ip not in nm.all_hosts():
            return resultado
        hostnames = nm[ip].get('hostnames', [])
        if hostnames:
            resultado['hostname'] = hostnames[0].get('name', 'unknown') or 'unknown'
        if 'osmatch' in nm[ip] and nm[ip]['osmatch']:
            resultado['os_info'] = nm[ip]['osmatch'][0]['name']
            resultado['os_accuracy'] = nm[ip]['osmatch'][0].get('accuracy')
        servicios = []
        for proto in nm[ip].all_protocols():
            for port in nm[ip][proto]:
                svc = nm[ip][proto][port]
                service_dict = {
                    'port': port,
                    'proto': proto,
                    'service': svc.get('name', 'unknown'),
                    'version': svc.get('version', ''),
                    'product': svc.get('product', ''),
                    'extrainfo': svc.get('extrainfo', ''),
                    'cpe': svc.get('cpe', ''),
                    'vuln_results': {},
                    'vuln_errors': {}
                }
                vuln_info = svc.get('script', None)
                if vuln_info:
                    for key, value in vuln_info.items():
                        if "ERROR:" in value:
                            service_dict['vuln_errors'][key] = value
                        else:
                            service_dict['vuln_results'][key] = value
                servicios.append(service_dict)
        resultado['services'] = servicios
    except Exception as e:
        logging.exception(f"Error en escaneo detallado de {ip}: {e}")
    return resultado

###############################################################################
# Función que integra Quick Scan y Escaneo Detallado
###############################################################################
def escaneo_completo(ip: str, nmap_options: str = None) -> dict:
    """
    Para la IP dada, realiza primero un quick scan para detectar puertos abiertos y,
    si se encuentran, ejecuta el escaneo detallado sobre esos puertos.
    Retorna un diccionario con toda la información obtenida.
    """
    open_ports = quick_scan(ip)
    logging.debug(f"Quick scan en {ip} - Puertos abiertos: {open_ports}")
    resultado = escaneo_detallado(ip, open_ports, nmap_options)
    resultado['open_ports'] = open_ports
    return resultado

###############################################################################
# Función para clasificar el tipo de dispositivo
###############################################################################
def classify_device(os_info: str, services: List[Dict[str, Any]], mac: str = None) -> str:
    os_lower = os_info.lower()
    # Base de datos simplificada de OUI para identificar fabricante
    oui_db = {
        '00:1A:2B': 'Cisco',
        '00:1B:2C': 'Cisco',
        '00:1C:42': 'Apple',
    }
    if mac:
        for oui, fabricante in oui_db.items():
            if mac.upper().startswith(oui):
                if fabricante.lower() == 'cisco':
                    return "Router/Switch/Firewall Cisco"
    if 'fortinet' in os_lower or 'fortigate' in os_lower:
        return "Firewall/Appliance Fortinet"
    elif 'cisco' in os_lower or 'ios' in os_lower or 'nx-os' in os_lower:
        return "Router/Switch/Firewall Cisco"
    elif 'windows' in os_lower:
        return "Equipo con Windows"
    elif 'linux' in os_lower or 'unix' in os_lower:
        if any(svc for svc in services if svc.get('port') == 22 and 'openssh' in svc.get('service', '').lower()):
            return "Servidor Linux-Unix"
        return "Dispositivo Linux/Unix"
    elif 'android' in os_lower:
        return "Dispositivo móvil"
    else:
        ports = [str(svc['port']) for svc in services]
        if '80' in ports or '443' in ports:
            return "Servidor Web"
        return "Dispositivo desconocido"

###############################################################################
# Función auxiliar para formatear el mensaje de detección
###############################################################################
def format_detection_message(detection: dict, log_type: str) -> str:
    """
    Devuelve una cadena con el mensaje de detección en el formato solicitado.
    Si log_type es 'json', retorna un JSON formateado; si es 'syslog', usa '||' como separador.
    """
    if log_type == 'json':
        return json.dumps(detection)
    else:
        # Construir string para syslog con separador ||
        servicios = []
        for svc in detection.get("services", []):
            svc_str = (f"{svc['port']}/{svc['proto']}("
                       f"service: {svc['service']}, version: {svc['version']}, "
                       f"product: {svc['product']}, extrainfo: {svc['extrainfo']}, cpe: {svc['cpe']}) ")
            servicios.append(svc_str)
        servicios_str = "; ".join(servicios)
        return (f"[DETECCIÓN] IP={detection.get('ip')} || MAC={detection.get('mac')} || "
                f"Hostname={detection.get('hostname')} || OS={detection.get('os_info')} || "
                f"Tipo={detection.get('device_type')} || Puertos abiertos={detection.get('open_ports')} || "
                f"Servicios=[{servicios_str}]")

###############################################################################
# Proceso principal
###############################################################################
def main():
    args = parse_arguments()
    configurar_logging(args.log_server, args.debug, args.log_type)
    
    if args.public_ip:
        public_ip = obtener_ip_publica()
        print(f"IP Pública: {public_ip}")
        sys.exit(0)

    logging.info("========== Iniciando LAN Radar ==========")
    ips_de_zeek = obtener_ips_de_zeek_connlog(args.zeek_log)
    if not ips_de_zeek:
        logging.info("No se encontraron IPs en conn.log. Finalizando.")
        sys.exit(0)
    ips_filtradas = [ip for ip in ips_de_zeek if es_ip_privada_y_no_multicast_broadcast(ip)]
    logging.info(f"IPs totales: {len(ips_de_zeek)}; Tras filtrado: {len(ips_filtradas)}.")

    ip_mac_registradas = leer_ip_mac_registry(args.registry)
    nm = nmap.PortScanner()
    mac_map = obtener_mac_todas_las_ips(nm, ips_filtradas)

    ips_a_escanear = []
    for ip in ips_filtradas:
        nueva_mac = mac_map.get(ip)
        if not nueva_mac:
            logging.warning(f"Saltando {ip} por no obtener MAC real.")
            continue
        mac_registrada = ip_mac_registradas.get(ip)
        if mac_registrada == nueva_mac:
            continue
        actualizar_ip_mac_registry(args.registry, ip, nueva_mac)
        ips_a_escanear.append(ip)
    if not ips_a_escanear:
        logging.info("No hay IPs nuevas o con MAC modificada. Finalizando.")
        sys.exit(0)

    logging.info(f"Escaneando en detalle {len(ips_a_escanear)} IPs en paralelo.")
    cpu_count = multiprocessing.cpu_count()
    pool_size = min(len(ips_a_escanear), cpu_count * 2)
    with multiprocessing.Pool(processes=pool_size) as pool:
        resultados = pool.starmap(escaneo_completo, [(ip, args.nmap_options) for ip in ips_a_escanear])

    # Procesar cada resultado y formatear el mensaje de detección
    for info in resultados:
        ip = info['ip']
        mac = mac_map.get(ip, 'N/A')
        hostname = info['hostname']
        os_info = info['os_info']
        device_type = classify_device(os_info, info['services'], mac=mac)
        detection = {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "os_info": os_info,
            "device_type": device_type,
            "open_ports": info.get('open_ports', []),
            "services": info.get('services', [])
        }
        message = format_detection_message(detection, args.log_type)
        logging.info(message)
    logging.info("Escaneo completo. Fin.")

if __name__ == '__main__':
    main()
