"""
Módulo para parsear archivos de escaneo Nmap y extraer información relevante.
"""

import re
import os
import xml.etree.ElementTree as ET


def es_dominio_valido(hostname):
    """Valida que el hostname sea un dominio completo con TLD (ej: example.com, subdomain.example.net)"""
    if not hostname:
        return False
    
    # No debe ser una IP
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
        return False
    
    # Debe tener al menos un punto (para tener TLD)
    if '.' not in hostname:
        return False
    
    # Debe terminar con un TLD válido (al menos 2 caracteres después del último punto)
    # Patrón: al menos un punto seguido de 2+ caracteres alfanuméricos
    if not re.search(r'\.[a-zA-Z0-9]{2,}$', hostname):
        return False
    
    # No debe terminar con punto (dominios incompletos como "cloudfront.")
    if hostname.endswith('.'):
        return False
    
    # Validar formato básico de dominio
    # Debe contener solo letras, números, guiones y puntos
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$', hostname):
        return False
    
    return True


def procesar_gnmap(archivo_entrada):
    """Procesa un archivo .gnmap y extrae información de hosts, puertos ABIERTOS (SIN HOSTNAMES)"""
    resultados = []
    ips_en_alcance = []
    nombre_archivo = os.path.basename(archivo_entrada)

    with open(archivo_entrada, "r") as f:
        for linea in f:
            if linea.startswith("Host:"):
                # Capturar IP (NO extraer hostnames de .gnmap porque están incompletos)
                ip_match = re.search(r"Host:\s+(\d+\.\d+\.\d+\.\d+)", linea)
                
                if not ip_match:
                    continue
                
                ip = ip_match.group(1)

                if "Ports:" in linea:
                    puertos = linea.split("Ports:")[1].split("Ignored")[0].strip()
                    for p in puertos.split(","):
                        p = p.strip()
                        partes = p.split("/")
                        if len(partes) >= 2:
                            puerto = partes[0]
                            estado = partes[1]

                            if estado != "open":
                                continue

                            protocolo = partes[2] if len(partes) >= 3 else ""
                            servicio = partes[4] if len(partes) >= 5 else ""
                            version = ""
                            if len(partes) >= 7:
                                version = partes[6]

                            resultados.append({
                                "archivo_origen": nombre_archivo,
                                "ip": ip,
                                "hostnames": "",  # NO extraer hostnames de .gnmap
                                "puerto": puerto,
                                "protocolo": protocolo,
                                "estado": estado,
                                "servicio": servicio,
                                "version": version
                            })

                            if ip not in ips_en_alcance:
                                ips_en_alcance.append(ip)

    return resultados, ips_en_alcance


def limpiar_version(version_texto, servicio="", puerto="", producto="", extrainfo=""):
    """
    Limpia y mejora el texto de versión, evitando valores como 'syn-ack ttl 64'
    Busca en múltiples fuentes: version_texto, producto, extrainfo
    Si no hay versión válida, usa el nombre del servicio o servicio por puerto
    """
    # Intentar múltiples fuentes de información
    fuentes = []
    if version_texto:
        fuentes.append(version_texto.strip())
    if producto:
        fuentes.append(producto.strip())
    if extrainfo:
        fuentes.append(extrainfo.strip())
    
    # Patrones a evitar (respuestas de TCP, no versiones reales)
    patrones_invalidos = [
        r'^syn-ack',
        r'^syn-ack\s+ttl',
        r'syn-ack\s+ttl\s+\d+',
        r'ttl\s+\d+',
        r'^closed',
        r'^filtered',
        r'^unreachable',
        r'^reset',
        r'^no\s+response',
        r'^timeout',
        r'^refused',
        r'^tcpwrapped',
        r'^unknown',
        r'^open\s*$',
        r'^\s*$',
        r'^tcp\s*$',
        r'^udp\s*$',
        r'^service\s*$',
        r'^product:\s*$',
        r'^version:\s*$'
    ]
    
    # Buscar la primera versión válida de todas las fuentes
    version_final = ""
    for fuente in fuentes:
        if not fuente or len(fuente) < 2:
            continue
        
        # Verificar si es un patrón inválido
        es_invalido = False
        for patron in patrones_invalidos:
            if re.match(patron, fuente, re.IGNORECASE):
                es_invalido = True
                break
        
        if not es_invalido:
            # Verificar que no sea solo el nombre del servicio
            if fuente.lower() != servicio.lower() if servicio else True:
                version_final = fuente
                break
    
    # Si después de limpiar no hay versión, intentar obtener de servicio
    if not version_final or len(version_final) < 2:
        # Usar servicio si está disponible y es válido
        if servicio and servicio.lower() not in ['unknown', 'tcp', 'udp', '', 'service']:
            version_final = servicio
        # Si no hay servicio, usar servicio por puerto conocido
        elif puerto:
            version_final = obtener_servicio_por_puerto(puerto)
        else:
            version_final = servicio if servicio else ""
    
    # Limitar longitud
    if len(version_final) > 100:
        version_final = version_final[:100] + "..."
    
    return version_final


def obtener_servicio_por_puerto(puerto):
    """Obtiene el nombre del servicio estándar para un puerto conocido"""
    from config import SCRIPTS_POR_PUERTO
    if puerto in SCRIPTS_POR_PUERTO:
        return SCRIPTS_POR_PUERTO[puerto]["servicio"]
    
    # Servicios comunes por puerto
    servicios_comunes = {
        "21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP", "53": "DNS",
        "80": "HTTP", "110": "POP3", "143": "IMAP", "443": "HTTPS", "445": "SMB",
        "3306": "MySQL", "3389": "RDP", "5432": "PostgreSQL", "8080": "HTTP-Proxy",
        "8443": "HTTPS-Alt", "27017": "MongoDB", "6379": "Redis"
    }
    
    return servicios_comunes.get(puerto, "Unknown")


def procesar_nmap(archivo_entrada):
    """Procesa un archivo .nmap y extrae información de hosts, puertos ABIERTOS y DOMINIOS COMPLETOS"""
    resultados = []
    ips_en_alcance = []
    nombre_archivo = os.path.basename(archivo_entrada)
    
    ip_actual = None
    hostnames_actuales = []
    
    with open(archivo_entrada, "r", encoding='utf-8', errors='ignore') as f:
        lineas = f.readlines()
    
    i = 0
    while i < len(lineas):
        linea = lineas[i].strip()
        
        # Buscar línea "Nmap scan report for"
        if "Nmap scan report for" in linea:
            # Guardar resultados del host anterior si existe
            if ip_actual:
                hostnames_str = ", ".join(hostnames_actuales) if hostnames_actuales else ""
                # Los resultados ya se agregaron en el procesamiento de puertos
            
            # Resetear para nuevo host
            ip_actual = None
            hostnames_actuales = []
            
            match1 = re.search(r"Nmap scan report for\s+(.+?)\s+\((\d+\.\d+\.\d+\.\d+)\)", linea)
            if match1:
                hostname = match1.group(1).strip()
                ip_actual = match1.group(2).strip()
                
                if es_dominio_valido(hostname):
                    if hostname not in hostnames_actuales:
                        hostnames_actuales.append(hostname)
                elif ',' in hostname or ' ' in hostname:
                    hostnames_separados = re.split(r'[,\s]+', hostname)
                    for hn in hostnames_separados:
                        hn_clean = hn.strip()
                        if es_dominio_valido(hn_clean) and hn_clean not in hostnames_actuales:
                            hostnames_actuales.append(hn_clean)
            else:
                match2 = re.search(r"Nmap scan report for\s+(\d+\.\d+\.\d+\.\d+)", linea)
                if match2:
                    ip_actual = match2.group(1).strip()
                else:
                    match3 = re.search(r"Nmap scan report for\s+(.+?)$", linea)
                    if match3:
                        hostname = match3.group(1).strip()
                        j = i + 1
                        while j < min(i + 10, len(lineas)) and not ip_actual:
                            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", lineas[j])
                            if ip_match:
                                ip_actual = ip_match.group(1).strip()
                                break
                            j += 1
                        if es_dominio_valido(hostname) and hostname not in hostnames_actuales:
                            hostnames_actuales.append(hostname)
        
        # Si tenemos una IP, buscar puertos abiertos
        if ip_actual:
            # Buscar líneas de puertos: "PORT     STATE SERVICE" seguido de líneas como "80/tcp   open  http"
            if re.match(r'^\d+/\w+\s+open\s+', linea):
                partes = linea.split()
                if len(partes) >= 2:
                    puerto_protocolo = partes[0]
                    estado = partes[1]
                    
                    if estado == "open":
                        puerto_match = re.match(r'^(\d+)/(\w+)', puerto_protocolo)
                        if puerto_match:
                            puerto = puerto_match.group(1)
                            protocolo = puerto_match.group(2)
                            servicio = partes[2] if len(partes) >= 3 else ""
                            version_raw = " ".join(partes[3:]) if len(partes) > 3 else ""
                            
                            # Buscar información adicional en líneas siguientes (producto, versión, etc.)
                            producto = ""
                            extrainfo = ""
                            j = i + 1
                            while j < min(i + 5, len(lineas)):  # Buscar en las siguientes 5 líneas
                                linea_sig = lineas[j].strip()
                                if not linea_sig or linea_sig.startswith("Nmap") or re.match(r'^\d+/\w+\s+', linea_sig):
                                    break
                                
                                # Buscar patrones de versión/producto
                                if "product:" in linea_sig.lower():
                                    producto = re.sub(r'.*product:\s*', '', linea_sig, flags=re.IGNORECASE).strip()
                                elif "version:" in linea_sig.lower():
                                    version_raw = re.sub(r'.*version:\s*', '', linea_sig, flags=re.IGNORECASE).strip()
                                elif "extrainfo:" in linea_sig.lower():
                                    extrainfo = re.sub(r'.*extrainfo:\s*', '', linea_sig, flags=re.IGNORECASE).strip()
                                elif producto and not version_raw and len(linea_sig) > 3:
                                    # Si hay producto pero no versión, la siguiente línea puede ser la versión
                                    if not re.match(r'^\d+/\w+\s+', linea_sig):
                                        version_raw = linea_sig
                                
                                j += 1
                            
                            # Limpiar versión buscando en múltiples fuentes
                            version = limpiar_version(version_raw, servicio, puerto, producto, extrainfo)
                            
                            # Si no hay servicio, usar servicio por puerto
                            if not servicio or servicio.lower() in ['unknown', 'tcp', 'udp', '']:
                                servicio = obtener_servicio_por_puerto(puerto)
                            
                            # Si no hay versión después de limpiar, usar servicio
                            if not version or version == servicio or len(version) < 2:
                                version = servicio
                            
                            hostnames_str = ", ".join(hostnames_actuales) if hostnames_actuales else ""
                            
                            resultados.append({
                                "archivo_origen": nombre_archivo,
                                "ip": ip_actual,
                                "hostnames": hostnames_str,
                                "puerto": puerto,
                                "protocolo": protocolo,
                                "estado": estado,
                                "servicio": servicio,
                                "version": version
                            })
                            
                            if ip_actual not in ips_en_alcance:
                                ips_en_alcance.append(ip_actual)
        
        i += 1

    return resultados, ips_en_alcance


def extraer_datos_xml(archivo_xml):
    """Extrae información detallada del archivo XML de Nmap, incluyendo HOSTNAMES"""
    datos = []
    
    try:
        tree = ET.parse(archivo_xml)
        root = tree.getroot()
        
        # Iterar sobre cada host
        for host in root.findall(".//host"):
            ip = host.find("address[@addrtype='ipv4']")
            if ip is None:
                continue
            ip_addr = ip.get("addr")
            
            # Extraer Hostnames
            hostnames_list = []
            hostnames_elem = host.find("hostnames")
            if hostnames_elem is not None:
                for hn in hostnames_elem.findall("hostname"):
                    name = hn.get("name")
                    if name:
                        hostnames_list.append(name)
            hostnames_str = ", ".join(hostnames_list)

            # Iterar sobre cada puerto
            for port in host.findall(".//port"):
                puerto = port.get("portid")
                estado_elem = port.find("state")
                estado = estado_elem.get("state") if estado_elem is not None else "unknown"
                
                if estado != "open":
                    continue
                
                servicio_elem = port.find("service")
                servicio_nombre = servicio_elem.get("name", "") if servicio_elem is not None else ""
                producto = servicio_elem.get("product", "") if servicio_elem is not None else ""
                version_raw = servicio_elem.get("version", "") if servicio_elem is not None else ""
                extrainfo = servicio_elem.get("extrainfo", "") if servicio_elem is not None else ""
                
                # Limpiar versión buscando en múltiples fuentes (version, producto, extrainfo)
                version = limpiar_version(version_raw, servicio_nombre, puerto, producto, extrainfo)
                
                # Si no hay servicio, usar servicio por puerto
                if not servicio_nombre or servicio_nombre.lower() in ['unknown', 'tcp', 'udp', '']:
                    servicio_nombre = obtener_servicio_por_puerto(puerto)
                
                # Si no hay versión válida, intentar con producto o servicio
                if not version or version == servicio_nombre or len(version) < 2:
                    if producto and producto.lower() not in ['unknown', 'tcp', 'udp', '']:
                        version = producto
                    else:
                        version = servicio_nombre
                
                servicio_info = {
                    "nombre": servicio_nombre,
                    "producto": producto,
                    "version": version,
                    "extrainfo": extrainfo,
                    "cpes": []
                }
                
                # Extraer CPEs (identidades de productos)
                if servicio_elem is not None:
                    for cpe in servicio_elem.findall("cpe"):
                        servicio_info["cpes"].append(cpe.text)
                
                # Extraer información de scripts
                scripts_info = {}
                for script in port.findall("script"):
                    script_id = script.get("id", "")
                    script_output = script.get("output", "")
                    
                    # Limitar longitud de output para mejor manejo
                    if len(script_output) > 500:
                        script_output = script_output[:500] + "..."
                    
                    scripts_info[script_id] = script_output
                
                datos.append({
                    "ip": ip_addr,
                    "hostnames": hostnames_str,
                    "puerto": puerto,
                    "estado": estado,
                    "servicio": servicio_info["nombre"],
                    "producto": servicio_info["producto"],
                    "version": servicio_info["version"],
                    "extrainfo": servicio_info["extrainfo"],
                    "cpes": " | ".join(servicio_info["cpes"]),
                    "scripts": scripts_info,
                    "archivo_origen": os.path.basename(archivo_xml)
                })
    
    except Exception as e:
        print(f"⚠ Error procesando XML {archivo_xml}: {str(e)}")
    
    return datos
