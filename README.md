# FAQ - LAN Radar V2

Este FAQ responde a las preguntas frecuentes sobre el proyecto LAN Radar V2, que incluye los siguientes archivos:

- **lanradar-v2.py:** El script principal para escanear y clasificar dispositivos en la red.
- **CHANGELOG:** Historial de cambios y mejoras entre versiones.
- **requirements.txt:** Lista de dependencias necesarias para ejecutar el script.

---

### 1. ¿Qué es LAN Radar V2?
LAN Radar V2 es un script en Python diseñado para escanear la red local. Extrae direcciones IP a partir de los logs de Zeek, ejecuta un escaneo rápido y un escaneo detallado usando nmap, y clasifica los dispositivos basándose en información como MAC, sistema operativo y puertos abiertos.

---

### 2. ¿Qué archivos componen este proyecto?
- **lanradar-v2.py:** Contiene toda la lógica del escaneo, clasificación y registro de dispositivos.
- **CHANGELOG:** Documenta las diferencias y mejoras realizadas respecto a versiones anteriores.
- **requirements.txt:** Especifica las dependencias externas (actualmente `python-nmap`) necesarias para ejecutar el script.

---

### 3. ¿Cómo instalo y configuro el proyecto?
1. **Requisitos previos:**
   - Tener instalado Python 3.
   - Instalar nmap en tu sistema, ya que el script lo utiliza para el escaneo.
2. **Instalación de dependencias:**
   Ejecuta el siguiente comando en la raíz del proyecto:
   ```bash
   pip install -r requirements.txt
   ```
3. **Configuración:**
   Puedes ajustar parámetros como la ruta al log de Zeek (`--zeek_log`), el archivo de registro IP-MAC (`--registry`), opciones adicionales para nmap (`--nmap_options`), y la configuración de logging (`--log_server`, `--log-type`, `--debug`).

---

### 4. ¿Cómo ejecuto el script?
Para ejecutar LAN Radar V2, utiliza la línea de comandos:
```bash
./lanradar-v2.py [opciones]
```
o
```bash
python lanradar-v2.py [opciones]
```
Por ejemplo, para ejecutar el script con un log de Zeek en la ubicación por defecto:
```bash
python lanradar-v2.py --zeek_log /opt/zeek/logs/current/conn.log
```

---

### 5. ¿Qué opciones de logging están disponibles?
El script permite configurar el logging en dos formatos:
- **Syslog:** Utiliza el separador `||` en los mensajes de log.
- **JSON:** Los mensajes se formatean como objetos JSON.
Puedes especificar el formato con el argumento `--log-type` y, opcionalmente, enviar los logs a un servidor remoto usando `--log_server`.

---

### 6. ¿Cómo clasifica LAN Radar V2 los dispositivos?
El proceso de clasificación se realiza en dos pasos:
1. **Escaneo Rápido y Detallado:**  
   Se realiza un quick scan para detectar puertos abiertos y, si se encuentran, un escaneo detallado para obtener información de versión, sistema operativo y vulnerabilidades.
2. **Clasificación:**  
   Con la información obtenida (incluyendo la dirección MAC, puertos y servicios), el script utiliza una función de clasificación para identificar el tipo de dispositivo (por ejemplo, Router/Switch, Servidor Linux-Unix, Equipo Windows, etc.).

---

### 7. ¿Dónde encuentro el historial de cambios?
Consulta el archivo **CHANGELOG** para conocer las diferencias entre las versiones (por ejemplo, mejoras y cambios implementados en la V2 respecto a la V1).

---

### 8. ¿A qué sistemas es compatible LAN Radar V2?
El script está escrito en Python y es compatible con sistemas que cuenten con Python 3 y nmap instalados. Está diseñado principalmente para sistemas Unix-like, dado que utiliza rutas y configuraciones propias de este tipo de sistemas (por ejemplo, `/var/log/nac/nac.log`).

---
