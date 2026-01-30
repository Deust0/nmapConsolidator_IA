"""
Módulo de análisis avanzado con IA para identificar vulnerabilidades
Analiza host por host y puerto por puerto para detectar hallazgos de seguridad
"""

import re
from typing import Dict, List, Optional
from config import SCRIPTS_POR_PUERTO


# Base de conocimiento de vulnerabilidades conocidas
VULNERABILITIES_DB = {
    "version_patterns": {
        "critical": [
            r"apache.*2\.(0|1|2|3|4)\.",
            r"nginx.*1\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16)\.",
            r"openssh.*(4|5|6|7)\.(0|1|2|3|4|5|6|7|8|9)\.",
            r"mysql.*(4|5)\.(0|1|2|3|4|5|6|7)\.",
            r"postgresql.*(7|8|9)\.(0|1|2|3|4)\.",
            r"php.*(4|5)\.(0|1|2|3|4|5|6)\.",
            r"wordpress.*(2|3|4)\.(0|1|2|3|4|5|6|7|8|9)\.",
            r"joomla.*(1|2|3)\.(0|1|2|3|4|5)\.",
            r"drupal.*(6|7)\.(0|1|2|3|4|5|6|7|8|9)\.",
            r"tomcat.*(5|6|7|8)\.(0|1|2|3|4|5)\.",
            r"jboss.*(4|5|6|7)\.(0|1|2|3|4|5)\.",
            r"weblogic.*(8|9|10|11|12)\.(0|1|2|3|4|5)\.",
            r"iis.*(6|7|8)\.(0|1|2|3|4|5)\.",
            r"exchange.*(2007|2010|2013)\.",
            r"sharepoint.*(2007|2010|2013)\.",
        ],
        "high": [
            r"apache.*2\.(4\.[0-9]|4\.[0-2][0-9])\.",
            r"nginx.*1\.(1[7-9]|2[0-2])\.",
            r"openssh.*(7\.[0-4]|8\.[0-2])\.",
            r"mysql.*5\.(5|6|7)\.",
            r"postgresql.*(9\.[0-5]|10)\.",
            r"php.*(5\.[3-6]|7\.[0-2])\.",
            r"wordpress.*(4\.[0-9]|5\.[0-3])\.",
            r"tomcat.*(8\.[0-5]|9\.[0-2])\.",
        ],
        "medium": [
            r"apache.*2\.4\.(2[4-9]|3[0-9]|4[0-7])\.",
            r"nginx.*1\.(1[8-9]|2[0-3])\.",
            r"openssh.*(7\.[5-9]|8\.[3-9])\.",
            r"mysql.*(5\.7\.[0-2][0-9]|8\.[0-1])\.",
            r"php.*(7\.[3-4]|8\.[0-1])\.",
        ]
    },
    "service_patterns": {
        "critical": [
            {"port": "21", "service": "FTP", "issues": ["Anonymous FTP enabled", "Weak authentication"]},
            {"port": "23", "service": "Telnet", "issues": ["Unencrypted protocol", "Weak authentication"]},
            {"port": "80", "service": "HTTP", "issues": ["Unencrypted web traffic", "Missing security headers"]},
            {"port": "135", "service": "RPC", "issues": ["Exposed RPC services", "Potential enumeration"]},
            {"port": "139", "service": "NETBIOS", "issues": ["Exposed NetBIOS", "Information disclosure"]},
            {"port": "445", "service": "SMB", "issues": ["Exposed SMB shares", "Potential lateral movement"]},
            {"port": "1433", "service": "MSSQL", "issues": ["Exposed database", "Default credentials risk"]},
            {"port": "3306", "service": "MySQL", "issues": ["Exposed database", "Weak authentication"]},
            {"port": "5432", "service": "PostgreSQL", "issues": ["Exposed database", "Weak authentication"]},
            {"port": "3389", "service": "RDP", "issues": ["Exposed remote desktop", "Brute force risk"]},
            {"port": "5985", "service": "WinRM", "issues": ["Exposed WinRM", "Remote management risk"]},
            {"port": "5986", "service": "WinRM", "issues": ["Exposed WinRM", "Remote management risk"]},
        ],
        "high": [
            {"port": "22", "service": "SSH", "issues": ["Weak SSH configuration", "Key-based auth missing"]},
            {"port": "25", "service": "SMTP", "issues": ["Open relay risk", "Information disclosure"]},
            {"port": "110", "service": "POP3", "issues": ["Unencrypted email", "Weak authentication"]},
            {"port": "143", "service": "IMAP", "issues": ["Unencrypted email", "Weak authentication"]},
            {"port": "161", "service": "SNMP", "issues": ["Default community strings", "Information disclosure"]},
            {"port": "389", "service": "LDAP", "issues": ["Exposed directory", "Information disclosure"]},
            {"port": "8080", "service": "HTTP-ALT", "issues": ["Unencrypted web traffic", "Management interface"]},
            {"port": "8443", "service": "HTTPS-ALT", "issues": ["Self-signed certificate", "Weak SSL/TLS"]},
        ],
        "medium": [
            {"port": "443", "service": "HTTPS", "issues": ["Weak SSL/TLS configuration", "Outdated ciphers"]},
            {"port": "993", "service": "IMAPS", "issues": ["Weak SSL/TLS", "Certificate issues"]},
            {"port": "995", "service": "POP3S", "issues": ["Weak SSL/TLS", "Certificate issues"]},
            {"port": "6379", "service": "Redis", "issues": ["No authentication", "Exposed cache"]},
            {"port": "27017", "service": "MongoDB", "issues": ["No authentication", "Exposed database"]},
        ],
        "low": [
            {"port": "53", "service": "DNS", "issues": ["DNS zone transfer", "Information disclosure"]},
            {"port": "111", "service": "RPCBIND", "issues": ["RPC enumeration", "Information disclosure"]},
        ]
    },
    "configuration_issues": {
        "critical": [
            "default credentials",
            "anonymous access",
            "no authentication",
            "weak encryption",
            "deprecated protocol",
        ],
        "high": [
            "self-signed certificate",
            "weak cipher",
            "missing security headers",
            "information disclosure",
            "version disclosure",
        ],
        "medium": [
            "outdated version",
            "missing updates",
            "default configuration",
            "excessive information",
        ]
    }
}


def analizar_version(version: str, servicio: str, puerto: str) -> List[Dict]:
    """
    Analiza la versión del servicio para identificar vulnerabilidades conocidas
    """
    hallazgos = []
    
    if not version or version.lower() in ["unknown", "tcp", "udp", servicio.lower()]:
        return hallazgos
    
    version_lower = version.lower()
    
    # Buscar patrones críticos
    for pattern in VULNERABILITIES_DB["version_patterns"]["critical"]:
        if re.search(pattern, version_lower, re.IGNORECASE):
            hallazgos.append({
                "severidad": "Crítica",
                "tipo": "Versión Vulnerable",
                "descripcion": f"Versión potencialmente vulnerable detectada: {version}",
                "recomendacion": f"Actualizar {servicio} a la versión más reciente y aplicar parches de seguridad",
                "cvss_base": 9.0,
                "categoria": "Vulnerabilidad de Versión"
            })
            break
    
    # Buscar patrones altos
    if not hallazgos:
        for pattern in VULNERABILITIES_DB["version_patterns"]["high"]:
            if re.search(pattern, version_lower, re.IGNORECASE):
                hallazgos.append({
                    "severidad": "Alta",
                    "tipo": "Versión Desactualizada",
                    "descripcion": f"Versión desactualizada detectada: {version}",
                    "recomendacion": f"Actualizar {servicio} a la versión más reciente",
                    "cvss_base": 7.5,
                    "categoria": "Vulnerabilidad de Versión"
                })
                break
    
    # Buscar patrones medios
    if not hallazgos:
        for pattern in VULNERABILITIES_DB["version_patterns"]["medium"]:
            if re.search(pattern, version_lower, re.IGNORECASE):
                hallazgos.append({
                    "severidad": "Media",
                    "tipo": "Versión Antigua",
                    "descripcion": f"Versión antigua detectada: {version}",
                    "recomendacion": f"Considerar actualizar {servicio} a la versión más reciente",
                    "cvss_base": 5.0,
                    "categoria": "Vulnerabilidad de Versión"
                })
                break
    
    return hallazgos


def analizar_servicio_puerto(puerto: str, servicio: str, version: str = "", hostname: str = "") -> List[Dict]:
    """
    Analiza un servicio en un puerto específico para identificar vulnerabilidades
    """
    hallazgos = []
    
    # Analizar por puerto y servicio
    for nivel_severidad in ["critical", "high", "medium", "low"]:
        for item in VULNERABILITIES_DB["service_patterns"].get(nivel_severidad, []):
            if item["port"] == puerto or item["service"].upper() == servicio.upper():
                for issue in item.get("issues", []):
                    severidad_map = {
                        "critical": "Crítica",
                        "high": "Alta",
                        "medium": "Media",
                        "low": "Baja"
                    }
                    
                    cvss_map = {
                        "critical": 9.0,
                        "high": 7.0,
                        "medium": 5.0,
                        "low": 3.0
                    }
                    
                    hallazgos.append({
                        "severidad": severidad_map[nivel_severidad],
                        "tipo": f"Riesgo de {item['service']}",
                        "descripcion": f"{issue} en puerto {puerto} ({servicio})",
                        "recomendacion": f"Implementar controles de seguridad adecuados para {servicio} en puerto {puerto}",
                        "cvss_base": cvss_map[nivel_severidad],
                        "categoria": "Configuración de Servicio"
                    })
                break
    
    # Analizar versión si está disponible
    if version:
        hallazgos_version = analizar_version(version, servicio, puerto)
        hallazgos.extend(hallazgos_version)
    
    # Análisis adicional basado en configuración
    if not hallazgos:
        # Servicios comunes sin autenticación
        servicios_sin_auth = ["redis", "mongodb", "memcached", "elasticsearch"]
        if servicio.lower() in servicios_sin_auth:
            hallazgos.append({
                "severidad": "Alta",
                "tipo": "Falta de Autenticación",
                "descripcion": f"Servicio {servicio} expuesto sin autenticación en puerto {puerto}",
                "recomendacion": f"Implementar autenticación para {servicio} o restringir acceso",
                "cvss_base": 7.5,
                "categoria": "Configuración de Seguridad"
            })
    
    return hallazgos


def analizar_host_completo(host_data: Dict) -> List[Dict]:
    """
    Analiza un host completo para identificar vulnerabilidades y patrones
    """
    hallazgos = []
    ip = host_data.get("ip", "")
    hostname = host_data.get("hostnames", "")
    puerto = host_data.get("puerto", "")
    servicio = host_data.get("servicio", "")
    version = host_data.get("version", "")
    producto = host_data.get("producto", "")
    extrainfo = host_data.get("extrainfo", "")
    cpes = host_data.get("cpes", "")
    
    # Analizar servicio específico
    hallazgos_servicio = analizar_servicio_puerto(puerto, servicio, version, hostname)
    hallazgos.extend(hallazgos_servicio)
    
    # Análisis de CPEs
    if cpes:
        for cpe in cpes.split("|"):
            cpe = cpe.strip()
            if cpe:
                # Extraer información de CPE
                # Formato: cpe:/a:vendor:product:version
                cpe_parts = cpe.split(":")
                if len(cpe_parts) >= 4:
                    vendor = cpe_parts[2] if len(cpe_parts) > 2 else ""
                    product = cpe_parts[3] if len(cpe_parts) > 3 else ""
                    version_cpe = cpe_parts[4] if len(cpe_parts) > 4 else ""
                    
                    if version_cpe:
                        hallazgos_cpe = analizar_version(version_cpe, product, puerto)
                        for hallazgo in hallazgos_cpe:
                            hallazgo["cpe"] = cpe
                        hallazgos.extend(hallazgos_cpe)
    
    # Análisis de información adicional
    if extrainfo:
        extrainfo_lower = extrainfo.lower()
        for nivel, keywords in VULNERABILITIES_DB["configuration_issues"].items():
            for keyword in keywords:
                if keyword in extrainfo_lower:
                    severidad_map = {
                        "critical": "Crítica",
                        "high": "Alta",
                        "medium": "Media"
                    }
                    cvss_map = {
                        "critical": 9.0,
                        "high": 7.0,
                        "medium": 5.0
                    }
                    
                    hallazgos.append({
                        "severidad": severidad_map.get(nivel, "Media"),
                        "tipo": "Problema de Configuración",
                        "descripcion": f"Problema detectado en información adicional: {extrainfo}",
                        "recomendacion": f"Revisar y corregir la configuración relacionada con: {keyword}",
                        "cvss_base": cvss_map.get(nivel, 5.0),
                        "categoria": "Configuración"
                    })
                    break
    
    # Agregar información del host a cada hallazgo
    for hallazgo in hallazgos:
        hallazgo["ip"] = ip
        hallazgo["hostname"] = hostname
        hallazgo["puerto"] = puerto
        hallazgo["servicio"] = servicio
        hallazgo["version"] = version
        hallazgo["estado"] = "Pendiente"  # Pendiente, Verificado, Falso Positivo, Confirmado
        hallazgo["fecha_deteccion"] = ""
        hallazgo["observaciones"] = ""
    
    return hallazgos


def analizar_resultados_completos(resultados: List[Dict]) -> List[Dict]:
    """
    Analiza todos los resultados para identificar vulnerabilidades
    """
    todos_hallazgos = []
    
    for resultado in resultados:
        hallazgos = analizar_host_completo(resultado)
        todos_hallazgos.extend(hallazgos)
    
    # Eliminar duplicados (mismo IP, puerto, tipo de hallazgo)
    hallazgos_unicos = []
    vistos = set()
    
    for hallazgo in todos_hallazgos:
        clave = (
            hallazgo.get("ip", ""),
            hallazgo.get("puerto", ""),
            hallazgo.get("tipo", ""),
            hallazgo.get("descripcion", "")[:50]  # Primeros 50 caracteres
        )
        if clave not in vistos:
            vistos.add(clave)
            hallazgos_unicos.append(hallazgo)
    
    return hallazgos_unicos


def obtener_resumen_vulnerabilidades(hallazgos: List[Dict]) -> Dict:
    """
    Genera un resumen estadístico de las vulnerabilidades encontradas
    """
    resumen = {
        "total": len(hallazgos),
        "criticas": 0,
        "altas": 0,
        "medias": 0,
        "bajas": 0,
        "pendientes": 0,
        "verificadas": 0,
        "falsos_positivos": 0,
        "confirmadas": 0,
        "por_categoria": {},
        "por_servicio": {}
    }
    
    for hallazgo in hallazgos:
        severidad = hallazgo.get("severidad", "")
        estado = hallazgo.get("estado", "Pendiente")
        categoria = hallazgo.get("categoria", "Otros")
        servicio = hallazgo.get("servicio", "Unknown")
        
        if severidad == "Crítica":
            resumen["criticas"] += 1
        elif severidad == "Alta":
            resumen["altas"] += 1
        elif severidad == "Media":
            resumen["medias"] += 1
        elif severidad == "Baja":
            resumen["bajas"] += 1
        
        if estado == "Pendiente":
            resumen["pendientes"] += 1
        elif estado == "Verificado":
            resumen["verificadas"] += 1
        elif estado == "Falso Positivo":
            resumen["falsos_positivos"] += 1
        elif estado == "Confirmado":
            resumen["confirmadas"] += 1
        
        resumen["por_categoria"][categoria] = resumen["por_categoria"].get(categoria, 0) + 1
        resumen["por_servicio"][servicio] = resumen["por_servicio"].get(servicio, 0) + 1
    
    return resumen
