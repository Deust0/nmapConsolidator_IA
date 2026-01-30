"""
Módulo para ejecutar escaneos de Nmap automáticamente.
"""

import os
import subprocess
import threading
from datetime import datetime
from queue import Queue
from typing import List, Dict, Callable, Optional

from config import PERFILES_ESCANEO


class NmapScanner:
    """Clase para gestionar escaneos de Nmap de forma paralela y controlada"""
    
    def __init__(self, max_threads=5, callback_progress: Optional[Callable] = None):
        """
        Inicializa el escáner de Nmap
        
        Args:
            max_threads: Número máximo de escaneos simultáneos
            callback_progress: Función callback para reportar progreso (ip, puerto, estado, mensaje)
        """
        self.max_threads = max_threads
        self.callback_progress = callback_progress
        self.scan_queue = Queue()
        self.results = []
        self.lock = threading.Lock()
        self.scan_count = 0
        self.total_scans = 0
    
    def ejecutar_escaneo_discovery(self, ip: str, puertos: List[str], carpeta_salida: str, port_option: str = None, perfil: str = "Estándar") -> Dict:
        """
        Ejecuta un escaneo de discovery (solo detección de puertos) para una IP
        
        Args:
            ip: Dirección IP a escanear
            puertos: Lista de puertos a escanear (ej: ["80", "443", "22"]) o None si se usa port_option
            carpeta_salida: Carpeta donde guardar los resultados
            port_option: Opción de puertos de nmap (ej: "--top-ports 1000", "1-65535")
            perfil: Perfil de escaneo a usar (Estándar, OT, VPN, Red Restrictiva)
        
        Returns:
            Dict con información del escaneo y archivos generados
        """
        os.makedirs(carpeta_salida, exist_ok=True)
        
        # Obtener configuración del perfil
        perfil_config = PERFILES_ESCANEO.get(perfil, PERFILES_ESCANEO["Estándar"])
        discovery_config = perfil_config["discovery"]
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archivo_base = os.path.join(carpeta_salida, f"nmap_discovery_{ip}_{timestamp}")
        
        # Comando de discovery con parámetros del perfil
        comando = [
            "nmap",
            discovery_config["scan_type"],  # Tipo de escaneo según perfil
            "-Pn",  # No hacer ping (asume host activo)
            "--min-rate", discovery_config["min_rate"],
            "--max-rate", discovery_config["max_rate"],
            "-oN", f"{archivo_base}.nmap",
            "-oX", f"{archivo_base}.xml",
            "-oG", f"{archivo_base}.gnmap",
        ]
        
        # Agregar opción de puertos
        if port_option and port_option.startswith("--top-ports"):
            # Formato: --top-ports 1000
            partes = port_option.split()
            comando.extend(partes)
        elif port_option:
            # Formato: 1-65535 o 80,443,22
            comando.extend(["-p", port_option])
        elif puertos:
            # Usar lista de puertos
            if len(puertos) == 1 and "-" in puertos[0]:
                # Es un rango
                comando.extend(["-p", puertos[0]])
            elif len(puertos) < 50:
                # Lista de puertos separados por comas
                puertos_str = ",".join(puertos)
                comando.extend(["-p", puertos_str])
            else:
                # Muchos puertos, usar rango
                puertos_int = [int(p) for p in puertos if p.isdigit()]
                if puertos_int:
                    comando.extend(["-p", f"{min(puertos_int)}-{max(puertos_int)}"])
                else:
                    comando.extend(["-p", "1-65535"])
        else:
            # Por defecto, top 1000 puertos
            comando.extend(["--top-ports", "1000"])
        
        comando.append(ip)
        
        try:
            if self.callback_progress:
                self.callback_progress(ip, "", "iniciando", f"Iniciando discovery para {ip}...")
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=discovery_config["timeout"]
            )
            
            archivos_generados = []
            for ext in [".nmap", ".xml", ".gnmap"]:
                archivo = f"{archivo_base}{ext}"
                if os.path.exists(archivo):
                    archivos_generados.append(archivo)
            
            estado = "completado" if resultado.returncode == 0 else "error"
            mensaje = f"Discovery completado para {ip}" if resultado.returncode == 0 else f"Error en discovery: {resultado.stderr[:100]}"
            
            if self.callback_progress:
                self.callback_progress(ip, "", estado, mensaje)
            
            return {
                "ip": ip,
                "tipo": "discovery",
                "estado": estado,
                "archivos": archivos_generados,
                "salida": resultado.stdout,
                "error": resultado.stderr if resultado.returncode != 0 else ""
            }
            
        except subprocess.TimeoutExpired:
            mensaje = f"Timeout en discovery para {ip}"
            if self.callback_progress:
                self.callback_progress(ip, "", "error", mensaje)
            return {
                "ip": ip,
                "tipo": "discovery",
                "estado": "timeout",
                "archivos": [],
                "salida": "",
                "error": "Timeout después de 5 minutos"
            }
        except Exception as e:
            mensaje = f"Excepción en discovery para {ip}: {str(e)}"
            if self.callback_progress:
                self.callback_progress(ip, "", "error", mensaje)
            return {
                "ip": ip,
                "tipo": "discovery",
                "estado": "error",
                "archivos": [],
                "salida": "",
                "error": str(e)
            }
    
    def ejecutar_escaneo_version(self, ip: str, puerto: str, servicio: str, carpeta_salida: str, perfil: str = "Estándar") -> Dict:
        """
        Ejecuta un escaneo de versión para un puerto específico
        
        Args:
            ip: Dirección IP
            puerto: Puerto a escanear
            servicio: Nombre del servicio (opcional, para scripts específicos)
            carpeta_salida: Carpeta donde guardar los resultados
            perfil: Perfil de escaneo a usar (Estándar, OT, VPN, Red Restrictiva)
        
        Returns:
            Dict con información del escaneo
        """
        os.makedirs(carpeta_salida, exist_ok=True)
        
        # Obtener configuración del perfil
        perfil_config = PERFILES_ESCANEO.get(perfil, PERFILES_ESCANEO["Estándar"])
        version_config = perfil_config["version"]
        
        from nmap_commands import obtener_scripts_para_puerto
        
        # Determinar scripts según perfil
        if version_config["scripts"]:
            scripts = obtener_scripts_para_puerto(puerto, servicio)
            scripts_str = ",".join(scripts) if scripts else ""
        else:
            # Sin scripts para perfiles OT
            scripts_str = ""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archivo_base = os.path.join(carpeta_salida, f"nmap_version_{ip}_{puerto}_{timestamp}")
        
        # Comando de versión con parámetros del perfil
        comando = [
            "nmap",
            "-sV",  # Version detection
            "-p", puerto,
            "--min-rate", version_config["min_rate"],
            "--max-rate", version_config["max_rate"],
            "--max-parallelism", version_config["max_parallelism"],
            "-oN", f"{archivo_base}.nmap",
            "-oX", f"{archivo_base}.xml",
        ]
        
        # Agregar scripts solo si están habilitados y hay scripts disponibles
        if version_config["scripts"] and scripts_str:
            comando.extend(["--script", scripts_str])
        
        comando.append(ip)
        
        try:
            if self.callback_progress:
                self.callback_progress(ip, puerto, "iniciando", f"Escaneando versión en {ip}:{puerto}...")
            
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=version_config["timeout"]
            )
            
            archivos_generados = []
            for ext in [".nmap", ".xml"]:
                archivo = f"{archivo_base}{ext}"
                if os.path.exists(archivo):
                    archivos_generados.append(archivo)
            
            estado = "completado" if resultado.returncode == 0 else "error"
            mensaje = f"Versión completada para {ip}:{puerto}" if resultado.returncode == 0 else f"Error: {resultado.stderr[:100]}"
            
            if self.callback_progress:
                self.callback_progress(ip, puerto, estado, mensaje)
            
            return {
                "ip": ip,
                "puerto": puerto,
                "tipo": "version",
                "estado": estado,
                "archivos": archivos_generados,
                "salida": resultado.stdout,
                "error": resultado.stderr if resultado.returncode != 0 else ""
            }
            
        except subprocess.TimeoutExpired:
            mensaje = f"Timeout en versión para {ip}:{puerto}"
            if self.callback_progress:
                self.callback_progress(ip, puerto, "error", mensaje)
            return {
                "ip": ip,
                "puerto": puerto,
                "tipo": "version",
                "estado": "timeout",
                "archivos": [],
                "salida": "",
                "error": f"Timeout después de {version_config['timeout']} segundos"
            }
        except Exception as e:
            mensaje = f"Excepción en versión para {ip}:{puerto}: {str(e)}"
            if self.callback_progress:
                self.callback_progress(ip, puerto, "error", mensaje)
            return {
                "ip": ip,
                "puerto": puerto,
                "tipo": "version",
                "estado": "error",
                "archivos": [],
                "salida": "",
                "error": str(e)
            }
    
    def _worker_thread(self):
        """Worker thread que procesa escaneos de la cola"""
        while True:
            item = self.scan_queue.get()
            if item is None:  # Señal de parada
                break
            
            tipo = item["tipo"]
            perfil = item.get("perfil", "Estándar")
            if tipo == "discovery":
                resultado = self.ejecutar_escaneo_discovery(
                    item["ip"],
                    item.get("puertos", []),
                    item["carpeta_salida"],
                    item.get("port_option"),
                    perfil
                )
            elif tipo == "version":
                resultado = self.ejecutar_escaneo_version(
                    item["ip"],
                    item["puerto"],
                    item.get("servicio", ""),
                    item["carpeta_salida"],
                    perfil
                )
            else:
                resultado = {"estado": "error", "error": "Tipo de escaneo desconocido"}
            
            with self.lock:
                self.results.append(resultado)
                self.scan_count += 1
            
            self.scan_queue.task_done()
    
    def ejecutar_escaneos_paralelos(self, tareas: List[Dict], carpeta_salida: str):
        """
        Ejecuta múltiples escaneos en paralelo
        
        Args:
            tareas: Lista de diccionarios con información de escaneos
                   Para discovery: {"tipo": "discovery", "ip": "...", "puertos": [...]}
                   Para version: {"tipo": "version", "ip": "...", "puerto": "...", "servicio": "..."}
            carpeta_salida: Carpeta base para guardar resultados
        """
        self.results = []
        self.scan_count = 0
        self.total_scans = len(tareas)
        
        # Preparar tareas con carpeta de salida
        for tarea in tareas:
            tarea["carpeta_salida"] = carpeta_salida
            self.scan_queue.put(tarea)
        
        # Iniciar threads workers
        threads = []
        for _ in range(min(self.max_threads, len(tareas))):
            thread = threading.Thread(target=self._worker_thread)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Esperar a que todas las tareas se completen
        self.scan_queue.join()
        
        # Detener workers
        for _ in range(len(threads)):
            self.scan_queue.put(None)
        
        for thread in threads:
            thread.join()
        
        return self.results
    
    def verificar_nmap_instalado(self) -> bool:
        """Verifica si nmap está instalado y disponible"""
        try:
            resultado = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                timeout=5
            )
            return resultado.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False
