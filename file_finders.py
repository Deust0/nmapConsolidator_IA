"""
Módulo para buscar archivos de escaneo Nmap en el sistema de archivos.
"""

import os
import glob


def buscar_archivos_gnmap(ruta=None):
    """Busca todos los archivos .gnmap en la ruta especificada o actual"""
    if ruta is None or ruta.strip() == "":
        ruta = os.getcwd()
    
    patron = os.path.join(ruta, "*.gnmap")
    archivos = glob.glob(patron)
    
    return archivos


def buscar_archivos_xml(ruta=None):
    """Busca todos los archivos XML de Nmap en la ruta especificada o actual"""
    if ruta is None or ruta.strip() == "":
        ruta = os.getcwd()
    
    # Buscar archivos nmap*.xml recursivamente
    archivos = []
    for root, dirs, files in os.walk(ruta):
        for file in files:
            if file.startswith("nmap") and file.endswith(".xml"):
                archivos.append(os.path.join(root, file))
    
    return archivos


def buscar_archivos_nmap(ruta=None):
    """Busca todos los archivos .nmap en la ruta especificada o actual"""
    if ruta is None or ruta.strip() == "":
        ruta = os.getcwd()
    
    patron = os.path.join(ruta, "*.nmap")
    archivos = glob.glob(patron)
    
    return archivos
