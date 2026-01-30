"""
Módulo para escribir archivos de salida (Excel, scripts, alcance, scope)
"""

import os
from datetime import datetime
import openpyxl
from config import PUERTOS_SSL_RECOMENDADOS
from excel_generator import (
    crear_hoja_resultados, crear_hoja_dashboard_vulnerabilidades,
    crear_hoja_resumen_ips, crear_hoja_seguimiento_vulnerabilidades,
    crear_hoja_matriz_riesgos, crear_hoja_analisis_ip,
    crear_hoja_comandos_mejorada, crear_hoja_info_escaneos,
    crear_hoja_instrucciones, crear_hoja_vulnerabilidades_detectadas
)
from nmap_commands import generar_comandos_ejecutables


def generar_scope_testssl(resultados, identificador, carpeta_base="resultados"):
    """Genera archivo scope para testssl.sh con formato host:puerto"""
    carpeta = f"{carpeta_base}_{identificador}"
    os.makedirs(carpeta, exist_ok=True)
    archivo_scope = os.path.join(carpeta, f"scope_testssl_{identificador}.txt")

    pares = set()
    for row in resultados:
        puerto = str(row.get("puerto", "")).strip()
        if puerto in PUERTOS_SSL_RECOMENDADOS:
            ip = row.get("ip", "").strip()
            # Si hay hostname, usarlo preferentemente para testssl si se desea, 
            # pero por consistencia usamos IP o Hostname según preferencia.
            # Aquí usamos IP:puerto por defecto, pero se podría cambiar.
            if ip:
                pares.add(f"{ip}:{puerto}")

    with open(archivo_scope, "w") as f:
        f.write("# Scope para testssl.sh - Puertos SSL/TLS detectados\n")
        f.write("# Generado automáticamente por Gestor de Vulnerabilidades\n")
        f.write(f"# Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("# Formato: host:puerto\n\n")
        for entrada in sorted(pares):
            f.write(entrada + "\n")

    print(f"✅ Scope para testssl generado: {archivo_scope}")
    return archivo_scope


def guardar_xlsx_completo(resultados, identificador, archivos_procesados, carpeta_base="resultados"):
    """Guarda resultados en XLSX con todas las hojas"""
    carpeta = f"{carpeta_base}_{identificador}"
    os.makedirs(carpeta, exist_ok=True)

    archivo_xlsx = os.path.join(carpeta, f"auditoria_{identificador}.xlsx")
    wb = openpyxl.Workbook()
    
    crear_hoja_resultados(wb, resultados)
    crear_hoja_vulnerabilidades_detectadas(wb, resultados)  # Nueva hoja con análisis IA
    crear_hoja_dashboard_vulnerabilidades(wb, resultados)
    crear_hoja_resumen_ips(wb, resultados)
    crear_hoja_seguimiento_vulnerabilidades(wb, resultados)
    crear_hoja_matriz_riesgos(wb, resultados)
    crear_hoja_analisis_ip(wb, resultados)
    crear_hoja_comandos_mejorada(wb, resultados)
    crear_hoja_info_escaneos(wb, archivos_procesados)
    crear_hoja_instrucciones(wb)
    
    wb.save(archivo_xlsx)
    print(f"✅ Excel profesional generado: {archivo_xlsx}")
    
    return carpeta


def guardar_scripts_ejecutables(resultados, carpeta_scripts):
    """Genera scripts bash ejecutables por IP"""
    os.makedirs(carpeta_scripts, exist_ok=True)
    
    ips_puertos = {}
    for row_data in resultados:
        ip = row_data.get("ip", "")
        puerto = row_data.get("puerto", "")
        servicio = row_data.get("servicio", "")
        version = row_data.get("version", "")
        
        if ip not in ips_puertos:
            ips_puertos[ip] = []
        ips_puertos[ip].append((puerto, servicio, version))
    
    for ip, puertos_lista in sorted(ips_puertos.items()):
        script_content = generar_comandos_ejecutables(ip, puertos_lista)
        archivo_script = os.path.join(carpeta_scripts, f"escaneo_{ip}.sh")
        with open(archivo_script, "w") as f:
            f.write(script_content)
        try:
            os.chmod(archivo_script, 0o755)
        except Exception:
            pass  # En Windows, chmod puede no funcionar, pero no es crítico
    
    print(f"✅ Scripts de escaneo generados en: {carpeta_scripts}")


def guardar_alcance(ips, identificador, carpeta):
    """Guarda archivo de alcance"""
    archivo_salida = os.path.join(carpeta, f"alcance_{identificador}.txt")
    with open(archivo_salida, "w") as f:
        f.write(f"# IPs con puertos abiertos - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Total: {len(ips)} hosts\n\n")
        for ip in sorted(ips):
            f.write(ip + "\n")
    print(f"✅ Archivo de alcance generado: {archivo_salida}")
