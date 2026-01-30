"""
Módulo para almacenar constantes y configuraciones globales.
"""

# Definir colores por severidad (RGB)
COLORES_SEVERIDAD = {
    "Crítica": "FF0000",                  # Rojo
    "Alta": "FF6600",                     # Naranja
    "Media": "FFD700",                    # Amarillo
    "Baja": "00B050",                     # Verde
    "Revisado - No vulnerable": "92D050", # Verde claro
    "Pendiente": "CCCCCC"                 # Gris
}

# Puertos típicos para escaneo SSL/TLS
PUERTOS_SSL_RECOMENDADOS = {
    "443", "8443", "9443",          # HTTPS variantes
    "993", "995",                   # IMAPS, POP3S
    "465", "587", "25",            # SMTPS / STARTTLS
    "110", "143",                  # POP3/IMAP STARTTLS
    "21", "990",                   # FTP/FTPS
    "389", "636",                  # LDAP/LDAPS
    "3389", "5986"                 # RDP TLS / WinRM
}

# Mapeo de puertos a scripts Nmap NO INTRUSIVOS
SCRIPTS_POR_PUERTO = {
    "21": {"servicio": "FTP", "scripts": ["ftp-anon", "ftp-bounce", "ftp-vsftpd-backdoor"]},
    "22": {"servicio": "SSH", "scripts": ["ssh-hostkey", "ssh-auth-methods", "ssh-brute"]},
    "25": {"servicio": "SMTP", "scripts": ["smtp-commands", "smtp-enum-users", "smtp-open-relay"]},
    "53": {"servicio": "DNS", "scripts": ["dns-brute", "dns-check-zone", "dns-nsid", "dns-recursion"]},
    "80": {"servicio": "HTTP", "scripts": ["http-title", "http-headers", "http-methods", "http-robots.txt", "http-git", "http-svn-enum", "http-webdav-scan", "http-iis-webdav-vuln"]},
    "110": {"servicio": "POP3", "scripts": ["pop3-capabilities"]},
    "111": {"servicio": "RPCBIND", "scripts": ["rpcinfo"]},
    "135": {"servicio": "RPC", "scripts": ["rpc-grind"]},
    "139": {"servicio": "NETBIOS", "scripts": ["smb-enum-shares", "smb-enum-users", "smb-os-discovery"]},
    "143": {"servicio": "IMAP", "scripts": ["imap-capabilities"]},
    "161": {"servicio": "SNMP", "scripts": ["snmp-info", "snmp-sysdescr", "snmp-processes"]},
    "389": {"servicio": "LDAP", "scripts": ["ldap-search", "ldap-rootdse"]},
    "443": {"servicio": "HTTPS", "scripts": ["ssl-cert", "ssl-enum-ciphers", "http-title", "http-headers", "http-methods", "http-robots.txt"]},
    "445": {"servicio": "SMB", "scripts": ["smb-enum-shares", "smb-enum-users", "smb-os-discovery", "smb-protocols", "smb-security-mode"]},
    "465": {"servicio": "SMTPS", "scripts": ["smtp-commands"]},
    "587": {"servicio": "SMTP", "scripts": ["smtp-commands", "smtp-open-relay"]},
    "636": {"servicio": "LDAPS", "scripts": ["ssl-cert", "ssl-enum-ciphers"]},
    "993": {"servicio": "IMAPS", "scripts": ["imap-capabilities"]},
    "995": {"servicio": "POP3S", "scripts": ["pop3-capabilities"]},
    "3306": {"servicio": "MySQL", "scripts": ["mysql-info", "mysql-users", "mysql-empty-password", "mysql-audit"]},
    "3389": {"servicio": "RDP", "scripts": ["rdp-enum-encryption"]},
    "5432": {"servicio": "PostgreSQL", "scripts": ["pgsql-brute"]},
    "5984": {"servicio": "CouchDB", "scripts": ["couchdb-databases"]},
    "6379": {"servicio": "Redis", "scripts": ["redis-info"]},
    "8080": {"servicio": "HTTP-ALT", "scripts": ["http-title", "http-headers", "http-methods", "http-robots.txt"]},
    "8443": {"servicio": "HTTPS-ALT", "scripts": ["ssl-cert", "http-title", "http-headers"]},
    "27017": {"servicio": "MongoDB", "scripts": ["mongodb-info"]},
    "50070": {"servicio": "Hadoop", "scripts": ["http-title"]}
}

# Perfiles de escaneo según el ambiente
PERFILES_ESCANEO = {
    "Estándar": {
        "nombre": "Estándar",
        "descripcion": "Escaneo normal para redes corporativas estándar",
        "discovery": {
            "min_rate": "100",
            "max_rate": "500",
            "timeout": 300,
            "scan_type": "-sS",  # SYN scan
            "agresividad": "media"
        },
        "version": {
            "min_rate": "20",
            "max_rate": "50",
            "max_parallelism": "5",
            "timeout": 180,
            "scripts": True,
            "agresividad": "media"
        }
    },
    "OT (Operational Technology)": {
        "nombre": "OT (Operational Technology)",
        "descripcion": "Escaneo muy conservador para redes industriales y SCADA",
        "discovery": {
            "min_rate": "10",
            "max_rate": "20",
            "timeout": 600,
            "scan_type": "-sS",
            "agresividad": "muy_baja"
        },
        "version": {
            "min_rate": "5",
            "max_rate": "10",
            "max_parallelism": "2",
            "timeout": 300,
            "scripts": False,  # Sin scripts para evitar afectar sistemas críticos
            "agresividad": "muy_baja"
        }
    },
    "VPN": {
        "nombre": "VPN",
        "descripcion": "Escaneo optimizado para conexiones VPN (más lento pero estable)",
        "discovery": {
            "min_rate": "50",
            "max_rate": "200",
            "timeout": 450,
            "scan_type": "-sS",
            "agresividad": "baja"
        },
        "version": {
            "min_rate": "10",
            "max_rate": "30",
            "max_parallelism": "3",
            "timeout": 240,
            "scripts": True,
            "agresividad": "baja"
        }
    },
    "Red Restrictiva": {
        "nombre": "Red Restrictiva",
        "descripcion": "Escaneo para redes con firewalls/IDS/IPS estrictos",
        "discovery": {
            "min_rate": "20",
            "max_rate": "100",
            "timeout": 600,
            "scan_type": "-sS",  # SYN scan más sigiloso
            "agresividad": "muy_baja"
        },
        "version": {
            "min_rate": "5",
            "max_rate": "20",
            "max_parallelism": "2",
            "timeout": 300,
            "scripts": True,  # Scripts básicos solo
            "agresividad": "muy_baja"
        }
    }
}
