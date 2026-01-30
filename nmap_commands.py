"""
Módulo para generar comandos Nmap inteligentes y herramientas específicas por servicio
"""

from datetime import datetime
from config import SCRIPTS_POR_PUERTO

# Mapeo de herramientas específicas por servicio (además de Nmap)
HERRAMIENTAS_POR_SERVICIO = {
    "HTTP": {
        "whatweb": "whatweb -a 3 {target}",
        "nikto": "nikto -h {target} -p {port}",
        "dirb": "dirb http://{target}:{port}/ /usr/share/wordlists/dirb/common.txt -o dirb_{target}_{port}.txt",
        "gobuster": "gobuster dir -u http://{target}:{port} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster_{target}_{port}.txt",
        "nuclei": "nuclei -u http://{target}:{port} -o nuclei_{target}_{port}.txt"
    },
    "HTTPS": {
        "testssl": "testssl.sh --quiet {target}:{port} | tee testssl_{target}_{port}.txt",
        "sslscan": "sslscan {target}:{port} | tee sslscan_{target}_{port}.txt",
        "sslyze": "sslyze {target}:{port} | tee sslyze_{target}_{port}.txt",
        "whatweb": "whatweb -a 3 https://{target}:{port}",
        "nikto": "nikto -h {target} -p {port} -ssl",
        "nuclei": "nuclei -u https://{target}:{port} -o nuclei_{target}_{port}.txt"
    },
    "FTP": {
        "ftp_banner": "echo 'QUIT' | nc -v {target} {port} | tee ftp_banner_{target}_{port}.txt",
        "hydra_enum": "hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt {target} ftp -o hydra_ftp_{target}_{port}.txt"
    },
    "SSH": {
        "ssh_audit": "ssh-audit {target}:{port} | tee ssh_audit_{target}_{port}.txt",
        "ssh_enum": "nmap -p {port} --script ssh-hostkey,ssh-auth-methods {target}"
    },
    "SMB": {
        "enum4linux": "enum4linux -a {target} | tee enum4linux_{target}.txt",
        "smbclient": "smbclient -L //{target} -N | tee smbclient_{target}.txt",
        "smbmap": "smbmap -H {target} | tee smbmap_{target}.txt",
        "crackmapexec": "crackmapexec smb {target} | tee crackmapexec_{target}.txt"
    },
    "MySQL": {
        "mysql_enum": "mysql -h {target} -P {port} -u root -e 'SHOW DATABASES;' 2>&1 | tee mysql_enum_{target}_{port}.txt",
        "mysql_audit": "mysql-audit -h {target} -P {port} | tee mysql_audit_{target}_{port}.txt"
    },
    "PostgreSQL": {
        "psql_enum": "psql -h {target} -p {port} -U postgres -l 2>&1 | tee psql_enum_{target}_{port}.txt"
    },
    "MongoDB": {
        "mongo_enum": "mongosh --host {target}:{port} --eval 'db.adminCommand(\"listDatabases\")' 2>&1 | tee mongo_enum_{target}_{port}.txt",
        "mongoaudit": "python3 mongoaudit.py {target}:{port} | tee mongoaudit_{target}_{port}.txt"
    },
    "Redis": {
        "redis_info": "redis-cli -h {target} -p {port} INFO | tee redis_info_{target}_{port}.txt",
        "redis_enum": "redis-cli -h {target} -p {port} CONFIG GET '*' | tee redis_config_{target}_{port}.txt"
    },
    "DNS": {
        "dnsrecon": "dnsrecon -d {target} -t std,brt | tee dnsrecon_{target}.txt",
        "dnsenum": "dnsenum {target} | tee dnsenum_{target}.txt"
    },
    "SMTP": {
        "smtp_enum": "smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {target} | tee smtp_enum_{target}_{port}.txt"
    },
    "SNMP": {
        "snmpwalk": "snmpwalk -c public -v2c {target} | tee snmpwalk_{target}_{port}.txt",
        "snmp_check": "snmp-check {target} | tee snmpcheck_{target}_{port}.txt"
    },
    "LDAP": {
        "ldapsearch": "ldapsearch -x -H ldap://{target}:{port} -b '' -s base | tee ldapsearch_{target}_{port}.txt"
    },
    "LDAPS": {
        "ldapsearch": "ldapsearch -x -H ldaps://{target}:{port} -b '' -s base | tee ldapsearch_{target}_{port}.txt"
    }
}


def obtener_herramientas_para_servicio(puerto, servicio=""):
    """Retorna las herramientas específicas para un servicio"""
    # Normalizar nombre de servicio
    servicio_upper = servicio.upper() if servicio else ""
    
    # Buscar por nombre de servicio
    if servicio_upper in HERRAMIENTAS_POR_SERVICIO:
        return HERRAMIENTAS_POR_SERVICIO[servicio_upper]
    
    # Buscar por puerto conocido
    if puerto in SCRIPTS_POR_PUERTO:
        servicio_por_puerto = SCRIPTS_POR_PUERTO[puerto]["servicio"]
        if servicio_por_puerto in HERRAMIENTAS_POR_SERVICIO:
            return HERRAMIENTAS_POR_SERVICIO[servicio_por_puerto]
    
    return {}


def obtener_scripts_para_puerto(puerto, servicio=""):
    """Retorna los scripts Nmap apropiados para un puerto específico"""
    if puerto in SCRIPTS_POR_PUERTO:
        return SCRIPTS_POR_PUERTO[puerto]["scripts"]
    
    scripts_genericos = ["banner", "service-version"]
    return scripts_genericos


def generar_comando_nmap_inteligente(ip, puerto, servicio="", version=""):
    """Genera comando Nmap inteligente y NO INTRUSIVO específico para el puerto"""
    scripts = obtener_scripts_para_puerto(puerto, servicio)
    scripts_str = ",".join(scripts)
    rate_params = "--min-rate 20 --max-rate 50 --max-parallelism 5"
    comando = f"nmap -sV -sC {ip} -p {puerto} --script={scripts_str} {rate_params} -oN nmap_{ip}_{puerto}.txt -oX nmap_{ip}_{puerto}.xml"
    return comando


def generar_comandos_ejecutables(ip, puertos_servicios):
    """
    Genera un script bash ejecutable con comandos Nmap y herramientas específicas por servicio
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    script_content = f"""#!/bin/bash
# Script de escaneo completo para {ip}
# Generado: {timestamp}
# Incluye: Nmap + Herramientas específicas por servicio
# Ver requirements_tools.txt para instalar herramientas necesarias

set -e  # Salir si hay errores

echo "=========================================="
echo "Iniciando escaneo completo para IP: {ip}"
echo "Fecha: $(date)"
echo "=========================================="

# Crear directorio de resultados
mkdir -p nmap_results_{ip}_{timestamp}
cd nmap_results_{ip}_{timestamp}

LOG_FILE="escaneo_{ip}_{timestamp}.log"
echo "Escaneo iniciado: $(date)" > $LOG_FILE
echo "IP: {ip}" >> $LOG_FILE
echo "" >> $LOG_FILE

# Función para verificar si una herramienta está instalada
check_tool() {{
    if command -v $1 &> /dev/null; then
        return 0
    else
        echo "⚠ ADVERTENCIA: $1 no está instalado. Instalar desde requirements_tools.txt" | tee -a $LOG_FILE
        return 1
    fi
}}

"""
    
    for puerto, servicio, version in puertos_servicios:
        servicio_norm = servicio.upper() if servicio else ""
        
        script_content += f"""
# ==========================================
# Puerto {puerto} - {servicio or 'Unknown'}
# ==========================================
echo "" | tee -a $LOG_FILE
echo "Escaneando puerto {puerto} ({servicio})..." | tee -a $LOG_FILE
echo "----------------------------------------" | tee -a $LOG_FILE

# 1. Escaneo Nmap
"""
        comando = generar_comando_nmap_inteligente(ip, puerto, servicio, version)
        script_content += f"echo \"[Nmap] Escaneando {ip}:{puerto}...\" | tee -a $LOG_FILE\n"
        script_content += f"{comando} | tee -a $LOG_FILE\n"
        script_content += f"echo \"[Nmap] Resultado guardado: nmap_{ip}_{puerto}.{{txt,xml}}\" | tee -a $LOG_FILE\n\n"
        
        # Agregar herramientas específicas por servicio
        herramientas = obtener_herramientas_para_servicio(puerto, servicio)
        if herramientas:
            script_content += f"# 2. Herramientas específicas para {servicio}\n"
            for nombre_herramienta, comando_herramienta in herramientas.items():
                # Reemplazar placeholders
                comando_herramienta = comando_herramienta.replace("{target}", ip).replace("{port}", puerto)
                
                # Extraer el comando base para verificar
                comando_base = nombre_herramienta.split('_')[0] if '_' in nombre_herramienta else nombre_herramienta
                
                script_content += f"""
# {nombre_herramienta}
if check_tool {comando_base}; then
    echo "[{nombre_herramienta}] Ejecutando..." | tee -a $LOG_FILE
    {comando_herramienta} 2>&1 | tee -a $LOG_FILE
    echo "[{nombre_herramienta}] Completado" | tee -a $LOG_FILE
else
    echo "[{nombre_herramienta}] Omitido (herramienta no disponible)" | tee -a $LOG_FILE
fi
"""
        
        script_content += f"\necho \"Puerto {puerto} completado\" | tee -a $LOG_FILE\n"
        script_content += f"echo \"\" | tee -a $LOG_FILE\n"
    
    script_content += f"""
echo "=========================================="
echo "Escaneo completado para IP: {ip}"
echo "Fecha: $(date)"
echo "=========================================="
echo "" | tee -a $LOG_FILE
echo "Resumen:" | tee -a $LOG_FILE
echo "- Archivos Nmap: nmap_{ip}_*.{{txt,xml}}" | tee -a $LOG_FILE
echo "- Archivos de herramientas: *_*.txt" | tee -a $LOG_FILE
echo "- Log completo: $LOG_FILE" | tee -a $LOG_FILE
echo "" | tee -a $LOG_FILE
echo "Para ver resultados: cat $LOG_FILE"
echo "Archivos en: $(pwd)"
"""
    return script_content
