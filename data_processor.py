"""
Módulo para procesar y combinar datos de múltiples archivos de escaneo
"""

from datetime import datetime
from parsers import procesar_gnmap, procesar_nmap, extraer_datos_xml


def procesar_multiples_gnmap(archivos):
    """Procesa múltiples archivos .gnmap"""
    todos_resultados = []
    todas_ips = set()
    
    for archivo in archivos:
        print(f"📄 Procesando GNMAP: {archivo}")
        resultados, ips = procesar_gnmap(archivo)
        todos_resultados.extend(resultados)
        todas_ips.update(ips)
    
    return todos_resultados, list(todas_ips)


def procesar_multiples_xml(archivos):
    """Procesa múltiples archivos XML de Nmap"""
    todos_resultados = []
    
    for archivo in archivos:
        print(f"📄 Procesando XML: {archivo}")
        resultados = extraer_datos_xml(archivo)
        todos_resultados.extend(resultados)
    
    return todos_resultados


def procesar_multiples_nmap(archivos):
    """Procesa múltiples archivos .nmap"""
    todos_resultados = []
    todas_ips = set()
    
    for archivo in archivos:
        print(f"📄 Procesando NMAP: {archivo}")
        resultados, ips = procesar_nmap(archivo)
        todos_resultados.extend(resultados)
        todas_ips.update(ips)
    
    return todos_resultados, list(todas_ips)


def deduplicar_y_combinar(resultados_gnmap, resultados_xml, resultados_nmap=None):
    """
    Deduplica y combina información priorizando: XML > NMAP > GNMAP
    GNMAP solo se usa como recurso opcional si no hay suficiente información
    """
    diccionario = {}
    
    # PRIORIDAD 1: Agregar datos de NMAP primero (más confiables que GNMAP)
    if resultados_nmap:
        for item in resultados_nmap:
            clave = f"{item['ip']}:{item['puerto']}"
            
            diccionario[clave] = {
                "archivo_origen": item.get("archivo_origen", ""),
                "ip": item.get("ip", ""),
                "hostnames": item.get("hostnames", ""),  # Hostnames de .nmap son válidos
                "puerto": item.get("puerto", ""),
                "protocolo": item.get("protocolo", ""),
                "estado": item.get("estado", "open"),
                "servicio": item.get("servicio", ""),
                "version": item.get("version", ""),
                "producto": "",
                "extrainfo": "",
                "cpes": "",
                "scripts": {}
            }
    
    # PRIORIDAD 2: Agregar/combinar datos de XML (más detallados, sobrescriben NMAP si hay conflicto)
    for item in resultados_xml:
        clave = f"{item['ip']}:{item['puerto']}"
        
        if clave not in diccionario:
            # Crear entrada nueva desde XML
            diccionario[clave] = {
                "archivo_origen": item.get("archivo_origen", ""),
                "ip": item.get("ip", ""),
                "hostnames": item.get("hostnames", ""),
                "puerto": item.get("puerto", ""),
                "protocolo": item.get("protocolo", ""),
                "estado": item.get("estado", "open"),
                "servicio": item.get("servicio", ""),
                "version": item.get("version", ""),
                "producto": item.get("producto", ""),
                "extrainfo": item.get("extrainfo", ""),
                "cpes": item.get("cpes", ""),
                "scripts": item.get("scripts", {})
            }
        else:
            # Combinar información, priorizando datos del XML
            if item.get("producto"):
                diccionario[clave]["producto"] = item["producto"]
            if item.get("version"):
                diccionario[clave]["version"] = item["version"]
            if item.get("servicio") and not diccionario[clave].get("servicio"):
                diccionario[clave]["servicio"] = item["servicio"]
            if item.get("extrainfo"):
                diccionario[clave]["extrainfo"] = item["extrainfo"]
            if item.get("cpes"):
                diccionario[clave]["cpes"] = item["cpes"]
            
            # Combinar hostnames de XML (son válidos)
            if item.get("hostnames"):
                hostnames_existentes = diccionario[clave].get("hostnames", "").split(", ") if diccionario[clave].get("hostnames") else []
                hostnames_nuevos = item["hostnames"].split(", ") if item["hostnames"] else []
                todos_hostnames = list(set([h.strip() for h in hostnames_existentes + hostnames_nuevos if h.strip()]))
                if todos_hostnames:
                    diccionario[clave]["hostnames"] = ", ".join(todos_hostnames)
            
            # Combinar scripts
            if item.get("scripts"):
                diccionario[clave]["scripts"].update(item["scripts"])
    
    # PRIORIDAD 3: GNMAP solo como recurso opcional (solo si falta información)
    for item in resultados_gnmap:
        clave = f"{item['ip']}:{item['puerto']}"
        
        if clave not in diccionario:
            # Solo crear entrada si no existe (GNMAP como último recurso)
            diccionario[clave] = {
                "archivo_origen": item.get("archivo_origen", ""),
                "ip": item.get("ip", ""),
                "hostnames": "",  # GNMAP no proporciona hostnames válidos
                "puerto": item.get("puerto", ""),
                "protocolo": item.get("protocolo", ""),
                "estado": item.get("estado", "open"),
                "servicio": item.get("servicio", ""),
                "version": item.get("version", ""),
                "producto": "",
                "extrainfo": "",
                "cpes": "",
                "scripts": {}
            }
        else:
            # Solo usar GNMAP si falta información crítica
            if not diccionario[clave].get("servicio") and item.get("servicio"):
                diccionario[clave]["servicio"] = item["servicio"]
            if not diccionario[clave].get("version") and item.get("version"):
                diccionario[clave]["version"] = item["version"]
            if not diccionario[clave].get("protocolo") and item.get("protocolo"):
                diccionario[clave]["protocolo"] = item["protocolo"]
            # NO combinar hostnames de GNMAP (siempre vacíos)
    
    return list(diccionario.values())


def generar_identificador(ips, num_archivos):
    """Genera un identificador único"""
    if not ips:
        return f"consolidado_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    fecha = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"consolidado_{len(ips)}hosts_{num_archivos}scans_{fecha}"
