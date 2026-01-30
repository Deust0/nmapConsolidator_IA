"""
Interfaz gráfica para el Gestor de Vulnerabilidades
Versión 10.0 - Con escaneos automáticos y GUI
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import sys
import threading
from datetime import datetime
from typing import List, Dict, Optional

from nmap_scanner import NmapScanner
from file_finders import buscar_archivos_gnmap, buscar_archivos_nmap, buscar_archivos_xml
from data_processor import (
    procesar_multiples_gnmap, procesar_multiples_nmap, procesar_multiples_xml,
    deduplicar_y_combinar, generar_identificador
)
from file_writers import guardar_xlsx_completo, guardar_scripts_ejecutables, guardar_alcance, generar_scope_testssl
from config import PERFILES_ESCANEO, COLORES_SEVERIDAD
from ai_analyzer import analizar_resultados_completos, obtener_resumen_vulnerabilidades


class VulnerabilitiesGUI:
    """Interfaz gráfica principal para el gestor de vulnerabilidades"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Gestor Profesional de Vulnerabilidades v10.0")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Variables de estado
        self.carpeta_resultados = None
        self.resultados_discovery = []
        self.resultados_finales = []
        self.identificador = None
        self.escaneando = False
        self.recursos_adicionales_discovery = []  # Lista de IPs/puertos adicionales para discovery
        self.recursos_adicionales_versions = []  # Lista de IPs/puertos adicionales para versiones
        self.vulnerabilidades_detectadas = []  # Lista de vulnerabilidades detectadas por IA
        self.resumen_vulnerabilidades = {}  # Resumen estadístico
        
        # Configurar estilo
        self.setup_ui()
        
        # Verificar nmap
        self.verificar_nmap()
    
    def setup_ui(self):
        """Configura la interfaz de usuario"""
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Título
        title_label = ttk.Label(
            main_frame,
            text="🔒 Gestor Profesional de Vulnerabilidades",
            font=("Arial", 16, "bold")
        )
        title_label.grid(row=0, column=0, pady=(0, 20))
        
        # Notebook para las fases
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        # Fase 1: Discovery
        self.setup_phase_discovery()
        
        # Fase 2: Versiones
        self.setup_phase_versions()
        
        # Fase 3: Excel Final
        self.setup_phase_excel()
        
        # Fase 4: Análisis de Vulnerabilidades
        self.setup_phase_vulnerabilities()
        
        # Área de log
        log_frame = ttk.LabelFrame(main_frame, text="Log de Actividad", padding="5")
        log_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, wrap=tk.WORD)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.log_text.config(state=tk.DISABLED)
    
    def setup_phase_discovery(self):
        """Configura la fase 1: Discovery"""
        frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(frame, text="Fase 1: Discovery")
        frame.columnconfigure(0, weight=1)
        
        # Título
        title = ttk.Label(
            frame,
            text="🔍 Escaneo de Discovery",
            font=("Arial", 14, "bold")
        )
        title.grid(row=0, column=0, pady=(0, 20))
        
        # Descripción
        desc = ttk.Label(
            frame,
            text="Ejecuta un escaneo inicial para descubrir puertos abiertos en los hosts objetivo.",
            wraplength=600
        )
        desc.grid(row=1, column=0, pady=(0, 20))
        
        # Input de IPs/Rangos
        ip_frame = ttk.LabelFrame(frame, text="Hosts a Escanear", padding="10")
        ip_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=10)
        ip_frame.columnconfigure(0, weight=1)
        
        ttk.Label(ip_frame, text="IPs o Rangos (una por línea):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ip_text = scrolledtext.ScrolledText(ip_frame, height=8, wrap=tk.WORD)
        self.ip_text.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        self.ip_text.insert("1.0", "192.168.1.1\n10.0.0.0/24\n")
        
        # Opciones de escaneo
        options_frame = ttk.LabelFrame(frame, text="Opciones de Escaneo", padding="10")
        options_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Label(options_frame, text="Puertos:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.port_var = tk.StringVar(value="--top-ports 1000")
        port_combo = ttk.Combobox(
            options_frame,
            textvariable=self.port_var,
            values=["--top-ports 100", "--top-ports 1000", "1-65535", "80,443,22,21,25,53,110,143,993,995"],
            state="readonly",
            width=30
        )
        port_combo.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(options_frame, text="Threads:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.threads_var = tk.StringVar(value="5")
        threads_spin = ttk.Spinbox(
            options_frame,
            from_=1,
            to=20,
            textvariable=self.threads_var,
            width=10
        )
        threads_spin.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(options_frame, text="Perfil de Escaneo:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.perfil_discovery_var = tk.StringVar(value="Estándar")
        perfil_combo = ttk.Combobox(
            options_frame,
            textvariable=self.perfil_discovery_var,
            values=list(PERFILES_ESCANEO.keys()),
            state="readonly",
            width=30
        )
        perfil_combo.grid(row=2, column=1, padx=5, pady=5)
        
        # Tooltip o descripción del perfil
        self.desc_perfil_discovery = ttk.Label(
            options_frame,
            text=PERFILES_ESCANEO["Estándar"]["descripcion"],
            wraplength=400,
            foreground="gray"
        )
        self.desc_perfil_discovery.grid(row=3, column=0, columnspan=2, sticky=tk.W, padx=5, pady=2)
        
        # Callback para actualizar descripción
        def actualizar_desc_perfil(event=None):
            perfil = self.perfil_discovery_var.get()
            if perfil in PERFILES_ESCANEO:
                self.desc_perfil_discovery.config(text=PERFILES_ESCANEO[perfil]["descripcion"])
        perfil_combo.bind("<<ComboboxSelected>>", actualizar_desc_perfil)
        
        # Recursos adicionales
        recursos_frame = ttk.LabelFrame(frame, text="Recursos Adicionales (Agregar durante escaneo)", padding="10")
        recursos_frame.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=10)
        recursos_frame.columnconfigure(0, weight=1)
        
        ttk.Label(recursos_frame, text="IPs o Rangos adicionales (una por línea):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.recursos_adicionales_text = scrolledtext.ScrolledText(recursos_frame, height=4, wrap=tk.WORD)
        self.recursos_adicionales_text.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        btn_frame = ttk.Frame(recursos_frame)
        btn_frame.grid(row=2, column=0, pady=5)
        
        ttk.Button(
            btn_frame,
            text="➕ Agregar al Alcance",
            command=self.agregar_recursos_discovery
        ).grid(row=0, column=0, padx=5)
        
        self.label_recursos_discovery = ttk.Label(recursos_frame, text="0 recursos adicionales agregados", foreground="blue")
        self.label_recursos_discovery.grid(row=3, column=0, pady=5)
        
        # Botón de ejecutar
        self.btn_discovery = ttk.Button(
            frame,
            text="▶ Iniciar Escaneo Discovery",
            command=self.ejecutar_discovery,
            style="Accent.TButton"
        )
        self.btn_discovery.grid(row=5, column=0, pady=20)
        
        # Progreso
        self.progress_discovery = ttk.Progressbar(frame, mode='indeterminate')
        self.progress_discovery.grid(row=6, column=0, sticky=(tk.W, tk.E), pady=10)
        
        self.status_discovery = ttk.Label(frame, text="Listo para escanear")
        self.status_discovery.grid(row=7, column=0)
    
    def agregar_recursos_discovery(self):
        """Agrega recursos adicionales al alcance de discovery"""
        recursos_text = self.recursos_adicionales_text.get("1.0", tk.END).strip()
        if not recursos_text:
            messagebox.showwarning("Sin recursos", "Por favor ingresa al menos una IP o rango.")
            return
        
        recursos = [r.strip() for r in recursos_text.split("\n") if r.strip()]
        self.recursos_adicionales_discovery.extend(recursos)
        
        # Agregar al texto principal
        contenido_actual = self.ip_text.get("1.0", tk.END)
        nuevos_recursos = "\n".join(recursos) + "\n"
        self.ip_text.insert(tk.END, nuevos_recursos)
        
        # Limpiar el campo de recursos adicionales
        self.recursos_adicionales_text.delete("1.0", tk.END)
        
        # Actualizar contador
        self.label_recursos_discovery.config(
            text=f"{len(self.recursos_adicionales_discovery)} recursos adicionales agregados"
        )
        
        self.log(f"➕ {len(recursos)} recursos adicionales agregados al alcance discovery")
        messagebox.showinfo("Recursos Agregados", f"Se agregaron {len(recursos)} recursos al alcance.")
    
    def setup_phase_versions(self):
        """Configura la fase 2: Versiones"""
        frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(frame, text="Fase 2: Versiones")
        frame.columnconfigure(0, weight=1)
        
        # Título
        title = ttk.Label(
            frame,
            text="🔬 Escaneo de Versiones",
            font=("Arial", 14, "bold")
        )
        title.grid(row=0, column=0, pady=(0, 20))
        
        # Descripción
        desc = ttk.Label(
            frame,
            text="Ejecuta escaneos de versión en los puertos descubiertos en la Fase 1.",
            wraplength=600
        )
        desc.grid(row=1, column=0, pady=(0, 20))
        
        # Seleccionar carpeta de resultados discovery
        folder_frame = ttk.LabelFrame(frame, text="Resultados Discovery", padding="10")
        folder_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=10)
        folder_frame.columnconfigure(0, weight=1)
        
        self.folder_discovery_var = tk.StringVar(value="")
        ttk.Label(folder_frame, text="Carpeta con resultados discovery:").grid(row=0, column=0, sticky=tk.W, pady=5)
        
        folder_input_frame = ttk.Frame(folder_frame)
        folder_input_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        folder_input_frame.columnconfigure(0, weight=1)
        
        self.folder_entry = ttk.Entry(folder_input_frame, textvariable=self.folder_discovery_var)
        self.folder_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        ttk.Button(
            folder_input_frame,
            text="📁 Buscar",
            command=self.seleccionar_carpeta_discovery
        ).grid(row=0, column=1)
        
        # Opciones de escaneo
        options_frame_versions = ttk.LabelFrame(frame, text="Opciones de Escaneo", padding="10")
        options_frame_versions.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Label(options_frame_versions, text="Perfil de Escaneo:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.perfil_versions_var = tk.StringVar(value="Estándar")
        perfil_combo_versions = ttk.Combobox(
            options_frame_versions,
            textvariable=self.perfil_versions_var,
            values=list(PERFILES_ESCANEO.keys()),
            state="readonly",
            width=30
        )
        perfil_combo_versions.grid(row=0, column=1, padx=5, pady=5)
        
        self.desc_perfil_versions = ttk.Label(
            options_frame_versions,
            text=PERFILES_ESCANEO["Estándar"]["descripcion"],
            wraplength=400,
            foreground="gray"
        )
        self.desc_perfil_versions.grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=5, pady=2)
        
        def actualizar_desc_perfil_versions(event=None):
            perfil = self.perfil_versions_var.get()
            if perfil in PERFILES_ESCANEO:
                self.desc_perfil_versions.config(text=PERFILES_ESCANEO[perfil]["descripcion"])
        perfil_combo_versions.bind("<<ComboboxSelected>>", actualizar_desc_perfil_versions)
        
        ttk.Label(options_frame_versions, text="Threads:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.threads_versions_var = tk.StringVar(value="5")
        threads_spin_versions = ttk.Spinbox(
            options_frame_versions,
            from_=1,
            to=20,
            textvariable=self.threads_versions_var,
            width=10
        )
        threads_spin_versions.grid(row=2, column=1, padx=5, pady=5)
        
        # Recursos adicionales para versiones
        recursos_frame_versions = ttk.LabelFrame(frame, text="Recursos Adicionales (IP:Puerto)", padding="10")
        recursos_frame_versions.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=10)
        recursos_frame_versions.columnconfigure(0, weight=1)
        
        ttk.Label(recursos_frame_versions, text="IP:Puerto adicionales (una por línea, ej: 192.168.1.1:443):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.recursos_adicionales_versions_text = scrolledtext.ScrolledText(recursos_frame_versions, height=4, wrap=tk.WORD)
        self.recursos_adicionales_versions_text.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        btn_frame_versions = ttk.Frame(recursos_frame_versions)
        btn_frame_versions.grid(row=2, column=0, pady=5)
        
        ttk.Button(
            btn_frame_versions,
            text="➕ Agregar al Alcance",
            command=self.agregar_recursos_versions
        ).grid(row=0, column=0, padx=5)
        
        self.label_recursos_versions = ttk.Label(recursos_frame_versions, text="0 recursos adicionales agregados", foreground="blue")
        self.label_recursos_versions.grid(row=3, column=0, pady=5)
        
        # Botón de procesar y escanear
        self.btn_versions = ttk.Button(
            frame,
            text="▶ Procesar Discovery y Escanear Versiones",
            command=self.ejecutar_versiones,
            style="Accent.TButton"
        )
        self.btn_versions.grid(row=5, column=0, pady=20)
        
        # Progreso
        self.progress_versions = ttk.Progressbar(frame, mode='determinate')
        self.progress_versions.grid(row=6, column=0, sticky=(tk.W, tk.E), pady=10)
        
        self.status_versions = ttk.Label(frame, text="Esperando resultados de Fase 1...")
        self.status_versions.grid(row=7, column=0)
        
        # Resumen
        self.resumen_versions = ttk.Label(frame, text="", wraplength=600)
        self.resumen_versions.grid(row=8, column=0, pady=10)
    
    def agregar_recursos_versions(self):
        """Agrega recursos adicionales (IP:Puerto) al alcance de versiones"""
        recursos_text = self.recursos_adicionales_versions_text.get("1.0", tk.END).strip()
        if not recursos_text:
            messagebox.showwarning("Sin recursos", "Por favor ingresa al menos un IP:Puerto.")
            return
        
        recursos = [r.strip() for r in recursos_text.split("\n") if r.strip() and ":" in r.strip()]
        self.recursos_adicionales_versions.extend(recursos)
        
        # Limpiar el campo
        self.recursos_adicionales_versions_text.delete("1.0", tk.END)
        
        # Actualizar contador
        self.label_recursos_versions.config(
            text=f"{len(self.recursos_adicionales_versions)} recursos adicionales agregados"
        )
        
        self.log(f"➕ {len(recursos)} recursos adicionales agregados al alcance de versiones")
        messagebox.showinfo("Recursos Agregados", f"Se agregaron {len(recursos)} recursos al alcance de versiones.")
    
    def setup_phase_excel(self):
        """Configura la fase 3: Excel Final"""
        frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(frame, text="Fase 3: Excel Final")
        frame.columnconfigure(0, weight=1)
        
        # Título
        title = ttk.Label(
            frame,
            text="📊 Generar Excel Final",
            font=("Arial", 14, "bold")
        )
        title.grid(row=0, column=0, pady=(0, 20))
        
        # Descripción
        desc = ttk.Label(
            frame,
            text="Genera el informe Excel completo con todos los resultados consolidados.",
            wraplength=600
        )
        desc.grid(row=1, column=0, pady=(0, 20))
        
        # Seleccionar carpeta de resultados finales
        folder_frame = ttk.LabelFrame(frame, text="Resultados Finales", padding="10")
        folder_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=10)
        folder_frame.columnconfigure(0, weight=1)
        
        self.folder_final_var = tk.StringVar(value="")
        ttk.Label(folder_frame, text="Carpeta con todos los resultados:").grid(row=0, column=0, sticky=tk.W, pady=5)
        
        folder_input_frame = ttk.Frame(folder_frame)
        folder_input_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        folder_input_frame.columnconfigure(0, weight=1)
        
        self.folder_final_entry = ttk.Entry(folder_input_frame, textvariable=self.folder_final_var)
        self.folder_final_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        ttk.Button(
            folder_input_frame,
            text="📁 Buscar",
            command=self.seleccionar_carpeta_final
        ).grid(row=0, column=1)
        
        # Botón de generar Excel
        self.btn_excel = ttk.Button(
            frame,
            text="▶ Generar Excel Final",
            command=self.generar_excel_final,
            style="Accent.TButton"
        )
        self.btn_excel.grid(row=3, column=0, pady=20)
        
        # Botón de abrir carpeta
        self.btn_abrir = ttk.Button(
            frame,
            text="📂 Abrir Carpeta de Resultados",
            command=self.abrir_carpeta_resultados
        )
        self.btn_abrir.grid(row=4, column=0, pady=10)
        
        # Status
        self.status_excel = ttk.Label(frame, text="Listo para generar Excel")
        self.status_excel.grid(row=5, column=0, pady=10)
    
    def log(self, mensaje: str):
        """Agrega un mensaje al log"""
        self.log_text.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {mensaje}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def verificar_nmap(self):
        """Verifica si nmap está instalado"""
        scanner = NmapScanner()
        if not scanner.verificar_nmap_instalado():
            messagebox.showwarning(
                "Nmap no encontrado",
                "Nmap no está instalado o no está en el PATH.\n"
                "Por favor, instala Nmap para usar esta herramienta.\n\n"
                "Windows: https://nmap.org/download.html\n"
                "Linux: sudo apt-get install nmap\n"
                "macOS: brew install nmap"
            )
            self.log("⚠ ADVERTENCIA: Nmap no encontrado en el sistema")
        else:
            self.log("✅ Nmap encontrado y listo")
    
    def seleccionar_carpeta_discovery(self):
        """Abre diálogo para seleccionar carpeta de resultados discovery"""
        carpeta = filedialog.askdirectory(title="Seleccionar carpeta con resultados discovery")
        if carpeta:
            self.folder_discovery_var.set(carpeta)
            self.log(f"📁 Carpeta discovery seleccionada: {carpeta}")
    
    def seleccionar_carpeta_final(self):
        """Abre diálogo para seleccionar carpeta de resultados finales"""
        carpeta = filedialog.askdirectory(title="Seleccionar carpeta con todos los resultados")
        if carpeta:
            self.folder_final_var.set(carpeta)
            self.log(f"📁 Carpeta final seleccionada: {carpeta}")
    
    def ejecutar_discovery(self):
        """Ejecuta la fase 1: Discovery"""
        if self.escaneando:
            messagebox.showwarning("Escaneo en curso", "Ya hay un escaneo en ejecución. Por favor espera.")
            return
        
        # Obtener IPs del texto
        ips_text = self.ip_text.get("1.0", tk.END).strip()
        if not ips_text:
            messagebox.showerror("Error", "Por favor ingresa al menos una IP o rango a escanear.")
            return
        
        ips = [ip.strip() for ip in ips_text.split("\n") if ip.strip()]
        if not ips:
            messagebox.showerror("Error", "No se encontraron IPs válidas.")
            return
        
        # Crear carpeta de resultados
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.carpeta_resultados = os.path.join(os.getcwd(), f"resultados_discovery_{timestamp}")
        os.makedirs(self.carpeta_resultados, exist_ok=True)
        
        self.log(f"🚀 Iniciando escaneo discovery para {len(ips)} host(s)")
        self.escaneando = True
        self.btn_discovery.config(state=tk.DISABLED)
        self.progress_discovery.start()
        self.status_discovery.config(text=f"Escaneando {len(ips)} host(s)...")
        
        # Ejecutar en thread separado
        thread = threading.Thread(target=self._ejecutar_discovery_thread, args=(ips,))
        thread.daemon = True
        thread.start()
    
    def _ejecutar_discovery_thread(self, ips: List[str]):
        """Thread para ejecutar discovery"""
        try:
            max_threads = int(self.threads_var.get())
            scanner = NmapScanner(max_threads=max_threads, callback_progress=self._callback_progress_discovery)
            
            # Preparar tareas
            port_option = self.port_var.get()
            perfil = self.perfil_discovery_var.get()
            tareas = []
            
            # Agregar IPs principales
            for ip in ips:
                tareas.append({
                    "tipo": "discovery",
                    "ip": ip,
                    "puertos": [],
                    "port_option": port_option,
                    "perfil": perfil
                })
            
            # Agregar recursos adicionales si hay
            for ip_adicional in self.recursos_adicionales_discovery:
                if ip_adicional not in ips:  # Evitar duplicados
                    tareas.append({
                        "tipo": "discovery",
                        "ip": ip_adicional,
                        "puertos": [],
                        "port_option": port_option,
                        "perfil": perfil
                    })
            
            # Ejecutar escaneos
            resultados = scanner.ejecutar_escaneos_paralelos(tareas, self.carpeta_resultados)
            
            self.resultados_discovery = resultados
            
            # Actualizar UI en thread principal
            self.root.after(0, self._discovery_completado, resultados)
            
        except Exception as e:
            self.root.after(0, self._discovery_error, str(e))
    
    def _callback_progress_discovery(self, ip: str, puerto: str, estado: str, mensaje: str):
        """Callback para actualizar progreso de discovery"""
        self.root.after(0, self.log, f"Discovery {ip}: {mensaje}")
    
    def _discovery_completado(self, resultados: List[Dict]):
        """Callback cuando discovery se completa"""
        self.escaneando = False
        self.btn_discovery.config(state=tk.NORMAL)
        self.progress_discovery.stop()
        
        exitosos = sum(1 for r in resultados if r.get("estado") == "completado")
        self.status_discovery.config(text=f"✅ Completado: {exitosos}/{len(resultados)} escaneos exitosos")
        self.log(f"✅ Discovery completado: {exitosos}/{len(resultados)} escaneos exitosos")
        
        messagebox.showinfo(
            "Discovery Completado",
            f"Escaneo discovery completado.\n"
            f"Exitosos: {exitosos}/{len(resultados)}\n\n"
            f"Resultados guardados en:\n{self.carpeta_resultados}"
        )
    
    def _discovery_error(self, error: str):
        """Callback cuando hay error en discovery"""
        self.escaneando = False
        self.btn_discovery.config(state=tk.NORMAL)
        self.progress_discovery.stop()
        self.status_discovery.config(text="❌ Error en discovery")
        self.log(f"❌ Error: {error}")
        messagebox.showerror("Error", f"Error durante discovery:\n{error}")
    
    def ejecutar_versiones(self):
        """Ejecuta la fase 2: Versiones"""
        if self.escaneando:
            messagebox.showwarning("Procesando", "Ya hay un proceso en ejecución. Por favor espera.")
            return
        
        carpeta = self.folder_discovery_var.get().strip()
        if not carpeta or not os.path.exists(carpeta):
            messagebox.showerror("Error", "Por favor selecciona una carpeta válida con resultados discovery.")
            return
        
        self.log(f"🔄 Procesando resultados discovery de: {carpeta}")
        self.escaneando = True
        self.btn_versions.config(state=tk.DISABLED)
        self.status_versions.config(text="Procesando...")
        
        # Ejecutar en thread separado
        thread = threading.Thread(target=self._ejecutar_versiones_thread, args=(carpeta,))
        thread.daemon = True
        thread.start()
    
    def _ejecutar_versiones_thread(self, carpeta: str):
        """Thread para ejecutar fase de versiones"""
        try:
            # 1. Procesar archivos discovery
            self.root.after(0, self.log, "📄 Buscando archivos de escaneo...")
            archivos_gnmap = buscar_archivos_gnmap(carpeta)
            archivos_nmap = buscar_archivos_nmap(carpeta)
            archivos_xml = buscar_archivos_xml(carpeta)
            
            if not archivos_gnmap and not archivos_nmap and not archivos_xml:
                self.root.after(0, self._versiones_error, "No se encontraron archivos de escaneo en la carpeta.")
                return
            
            self.root.after(0, self.log, f"📊 Procesando {len(archivos_gnmap)} .gnmap, {len(archivos_nmap)} .nmap, {len(archivos_xml)} .xml")
            
            resultados_gnmap, ips_gnmap = procesar_multiples_gnmap(archivos_gnmap)
            resultados_nmap, ips_nmap = procesar_multiples_nmap(archivos_nmap)
            resultados_xml = procesar_multiples_xml(archivos_xml)
            
            # Combinar resultados discovery
            todas_ips = list(set(ips_gnmap + ips_nmap))
            resultados = deduplicar_y_combinar(resultados_gnmap, resultados_xml, resultados_nmap)
            
            self.root.after(0, self.log, f"✅ Discovery procesado: {len(todas_ips)} hosts, {len(resultados)} puertos abiertos")
            
            # 2. Preparar escaneos de versión
            ips_puertos = {}
            for r in resultados:
                ip = r.get("ip", "")
                puerto = r.get("puerto", "")
                servicio = r.get("servicio", "")
                if ip and puerto:
                    if ip not in ips_puertos:
                        ips_puertos[ip] = []
                    ips_puertos[ip].append((puerto, servicio))
            
            # Agregar recursos adicionales (IP:Puerto)
            for recurso in self.recursos_adicionales_versions:
                if ":" in recurso:
                    try:
                        ip_adicional, puerto_adicional = recurso.split(":", 1)
                        ip_adicional = ip_adicional.strip()
                        puerto_adicional = puerto_adicional.strip()
                        if ip_adicional and puerto_adicional:
                            if ip_adicional not in ips_puertos:
                                ips_puertos[ip_adicional] = []
                            # Evitar duplicados
                            if (puerto_adicional, "") not in ips_puertos[ip_adicional]:
                                ips_puertos[ip_adicional].append((puerto_adicional, ""))
                    except ValueError:
                        self.root.after(0, self.log, f"⚠ Formato inválido en recurso adicional: {recurso}")
            
            total_escaneos = sum(len(puertos) for puertos in ips_puertos.values())
            self.root.after(0, self.log, f"🔬 Preparando {total_escaneos} escaneos de versión...")
            
            # Crear carpeta para versiones
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            carpeta_versiones = os.path.join(carpeta, f"versiones_{timestamp}")
            os.makedirs(carpeta_versiones, exist_ok=True)
            
            # Obtener perfil
            perfil = self.perfil_versions_var.get()
            
            # Preparar tareas
            tareas = []
            for ip, puertos_lista in ips_puertos.items():
                for puerto, servicio in puertos_lista:
                    tareas.append({
                        "tipo": "version",
                        "ip": ip,
                        "puerto": puerto,
                        "servicio": servicio,
                        "perfil": perfil
                    })
            
            # Ejecutar escaneos de versión
            max_threads = int(self.threads_versions_var.get())
            scanner = NmapScanner(max_threads=max_threads, callback_progress=self._callback_progress_versions)
            
            self.root.after(0, self.progress_versions.config, {"maximum": total_escaneos, "value": 0})
            
            resultados_versiones = scanner.ejecutar_escaneos_paralelos(tareas, carpeta_versiones)
            
            # 3. Procesar resultados finales
            self.root.after(0, self.log, "📊 Procesando resultados finales...")
            archivos_gnmap_final = buscar_archivos_gnmap(carpeta_versiones)
            archivos_nmap_final = buscar_archivos_nmap(carpeta_versiones)
            archivos_xml_final = buscar_archivos_xml(carpeta_versiones)
            
            resultados_gnmap_final, _ = procesar_multiples_gnmap(archivos_gnmap_final)
            resultados_nmap_final, _ = procesar_multiples_nmap(archivos_nmap_final)
            resultados_xml_final = procesar_multiples_xml(archivos_xml_final)
            
            # Combinar todos los resultados
            self.resultados_finales = deduplicar_y_combinar(
                resultados_gnmap + resultados_gnmap_final,
                resultados_xml + resultados_xml_final,
                resultados_nmap + resultados_nmap_final
            )
            
            self.identificador = generar_identificador(todas_ips, len(archivos_gnmap) + len(archivos_nmap) + len(archivos_xml))
            
            self.root.after(0, self._versiones_completado, total_escaneos, len(self.resultados_finales))
            
        except Exception as e:
            self.root.after(0, self._versiones_error, str(e))
    
    def _callback_progress_versions(self, ip: str, puerto: str, estado: str, mensaje: str):
        """Callback para actualizar progreso de versiones"""
        self.root.after(0, self.log, f"Versión {ip}:{puerto} - {mensaje}")
        if estado in ["completado", "error", "timeout"]:
            current = self.progress_versions["value"]
            self.root.after(0, self.progress_versions.config, {"value": current + 1})
    
    def _versiones_completado(self, total_escaneos: int, total_resultados: int):
        """Callback cuando versiones se completa"""
        self.escaneando = False
        self.btn_versions.config(state=tk.NORMAL)
        self.status_versions.config(text=f"✅ Completado: {total_escaneos} escaneos, {total_resultados} resultados")
        self.resumen_versions.config(
            text=f"✅ {total_escaneos} escaneos de versión completados\n"
                 f"📊 {total_resultados} resultados consolidados\n"
                 f"📁 Resultados en: {self.folder_discovery_var.get()}"
        )
        self.log(f"✅ Fase 2 completada: {total_escaneos} escaneos, {total_resultados} resultados")
        messagebox.showinfo(
            "Versiones Completado",
            f"Escaneo de versiones completado.\n\n"
            f"Escaneos ejecutados: {total_escaneos}\n"
            f"Resultados consolidados: {total_resultados}\n\n"
            "Ahora puedes generar el Excel final en la Fase 3."
        )
    
    def _versiones_error(self, error: str):
        """Callback cuando hay error en versiones"""
        self.escaneando = False
        self.btn_versions.config(state=tk.NORMAL)
        self.status_versions.config(text="❌ Error")
        self.log(f"❌ Error: {error}")
        messagebox.showerror("Error", f"Error durante escaneo de versiones:\n{error}")
    
    def generar_excel_final(self):
        """Genera el Excel final"""
        carpeta = self.folder_final_var.get().strip()
        if not carpeta or not os.path.exists(carpeta):
            messagebox.showerror("Error", "Por favor selecciona una carpeta válida con todos los resultados.")
            return
        
        if not self.resultados_finales:
            # Intentar procesar archivos de la carpeta
            self.log("📄 Procesando archivos de la carpeta...")
            archivos_gnmap = buscar_archivos_gnmap(carpeta)
            archivos_nmap = buscar_archivos_nmap(carpeta)
            archivos_xml = buscar_archivos_xml(carpeta)
            
            if not archivos_gnmap and not archivos_nmap and not archivos_xml:
                messagebox.showerror("Error", "No se encontraron archivos de escaneo en la carpeta.")
                return
            
            resultados_gnmap, ips_gnmap = procesar_multiples_gnmap(archivos_gnmap)
            resultados_nmap, ips_nmap = procesar_multiples_nmap(archivos_nmap)
            resultados_xml = procesar_multiples_xml(archivos_xml)
            
            todas_ips = list(set(ips_gnmap + ips_nmap))
            self.resultados_finales = deduplicar_y_combinar(resultados_gnmap, resultados_xml, resultados_nmap)
            self.identificador = generar_identificador(todas_ips, len(archivos_gnmap) + len(archivos_nmap) + len(archivos_xml))
        
        if not self.resultados_finales:
            messagebox.showerror("Error", "No hay resultados para generar el Excel.")
            return
        
        try:
            self.status_excel.config(text="Generando Excel...")
            self.log("📊 Generando Excel final...")
            
            # Buscar todos los archivos procesados
            archivos_todos = []
            for root, dirs, files in os.walk(carpeta):
                for file in files:
                    if file.endswith(('.gnmap', '.nmap', '.xml')) and 'nmap' in file.lower():
                        archivos_todos.append(os.path.join(root, file))
            
            carpeta_excel = guardar_xlsx_completo(
                self.resultados_finales,
                self.identificador,
                archivos_todos
            )
            
            todas_ips = list(set([r.get("ip", "") for r in self.resultados_finales if r.get("ip")]))
            guardar_alcance(todas_ips, self.identificador, carpeta_excel)
            generar_scope_testssl(self.resultados_finales, self.identificador, carpeta_base="resultados")
            
            self.carpeta_resultados = carpeta_excel
            self.status_excel.config(text=f"✅ Excel generado en: {carpeta_excel}")
            self.log(f"✅ Excel generado exitosamente: {carpeta_excel}")
            
            messagebox.showinfo(
                "Excel Generado",
                f"Excel generado exitosamente.\n\n"
                f"Ubicación: {carpeta_excel}\n"
                f"Archivo: auditoria_{self.identificador}.xlsx"
            )
            
        except Exception as e:
            self.status_excel.config(text="❌ Error al generar Excel")
            self.log(f"❌ Error: {str(e)}")
            messagebox.showerror("Error", f"Error al generar Excel:\n{str(e)}")
    
Total: {resumen['total']} | Críticas: {resumen['criticas']} | Altas: {resumen['altas']} | Medias: {resumen['medias']} | Bajas: {resumen['bajas']}
Pendientes: {resumen['pendientes']} | Verificadas: {resumen['verificadas']} | Falsos Positivos: {resumen['falsos_positivos']} | Confirmadas: {resumen['confirmadas']}"""
        
        self.resumen_text.insert("1.0", texto)
        self.resumen_text.config(state=tk.DISABLED)
    
    def aplicar_filtros(self):
        """Aplica filtros a la vista de vulnerabilidades"""
        self.actualizar_vista_vulnerabilidades()
    
    def limpiar_filtros(self):
        """Limpia los filtros aplicados"""
        self.filter_severidad_var.set("Todas")
        self.filter_estado_var.set("Todos")
        self.actualizar_vista_vulnerabilidades()
    
    def refrescar_vista_vulnerabilidades(self):
        """Refresca la vista de vulnerabilidades"""
        if self.vulnerabilidades_detectadas:
            self.actualizar_vista_vulnerabilidades()
            self.actualizar_resumen_vulnerabilidades()
        else:
            messagebox.showinfo("Sin datos", "No hay vulnerabilidades detectadas. Ejecuta el análisis primero.")
    
    def obtener_vulnerabilidad_seleccionada(self) -> Optional[Dict]:
        """Obtiene la vulnerabilidad seleccionada en el treeview"""
        seleccion = self.tree_vuln.selection()
        if not seleccion:
            return None
        
        item = seleccion[0]
        valores = self.tree_vuln.item(item, "values")
        
        if not valores:
            return None
        
        # Buscar en la lista de vulnerabilidades
        idx = int(valores[0]) - 1
        severidad_filtro = self.filter_severidad_var.get()
        estado_filtro = self.filter_estado_var.get()
        
        vulnerabilidades_filtradas = self.vulnerabilidades_detectadas.copy()
        if severidad_filtro != "Todas":
            vulnerabilidades_filtradas = [v for v in vulnerabilidades_filtradas if v.get("severidad") == severidad_filtro]
        if estado_filtro != "Todos":
            vulnerabilidades_filtradas = [v for v in vulnerabilidades_filtradas if v.get("estado") == estado_filtro]
        
        if 0 <= idx < len(vulnerabilidades_filtradas):
            return vulnerabilidades_filtradas[idx]
        
        return None
    
    def marcar_falso_positivo(self):
        """Marca la vulnerabilidad seleccionada como falso positivo"""
        vuln = self.obtener_vulnerabilidad_seleccionada()
        if not vuln:
            messagebox.showwarning("Sin selección", "Por favor selecciona una vulnerabilidad de la lista.")
            return
        
        vuln["estado"] = "Falso Positivo"
        self.log(f"❌ Vulnerabilidad marcada como Falso Positivo: {vuln.get('tipo')} en {vuln.get('ip')}:{vuln.get('puerto')}")
        self.actualizar_vista_vulnerabilidades()
        self.actualizar_resumen_vulnerabilidades()
        messagebox.showinfo("Actualizado", "Vulnerabilidad marcada como Falso Positivo.")
    
    def marcar_verificado(self):
        """Marca la vulnerabilidad seleccionada como verificada"""
        vuln = self.obtener_vulnerabilidad_seleccionada()
        if not vuln:
            messagebox.showwarning("Sin selección", "Por favor selecciona una vulnerabilidad de la lista.")
            return
        
        vuln["estado"] = "Verificado"
        from datetime import datetime
        vuln["fecha_verificacion"] = datetime.now().strftime("%Y-%m-%d")
        self.log(f"✅ Vulnerabilidad marcada como Verificada: {vuln.get('tipo')} en {vuln.get('ip')}:{vuln.get('puerto')}")
        self.actualizar_vista_vulnerabilidades()
        self.actualizar_resumen_vulnerabilidades()
        messagebox.showinfo("Actualizado", "Vulnerabilidad marcada como Verificada.")
    
    def marcar_confirmado(self):
        """Marca la vulnerabilidad seleccionada como confirmada"""
        vuln = self.obtener_vulnerabilidad_seleccionada()
        if not vuln:
            messagebox.showwarning("Sin selección", "Por favor selecciona una vulnerabilidad de la lista.")
            return
        
        vuln["estado"] = "Confirmado"
        from datetime import datetime
        vuln["fecha_confirmacion"] = datetime.now().strftime("%Y-%m-%d")
        self.log(f"🔴 Vulnerabilidad marcada como Confirmada: {vuln.get('tipo')} en {vuln.get('ip')}:{vuln.get('puerto')}")
        self.actualizar_vista_vulnerabilidades()
        self.actualizar_resumen_vulnerabilidades()
        messagebox.showinfo("Actualizado", "Vulnerabilidad marcada como Confirmada.")
    
    def analizar_vulnerabilidades(self):
        """Ejecuta análisis de vulnerabilidades con IA"""
        if not self.resultados_finales:
            messagebox.showwarning("Sin datos", "No hay resultados para analizar. Completa primero las fases anteriores.")
            return
        
        self.log("🤖 Iniciando análisis de vulnerabilidades con IA...")
        self.btn_analizar.config(state=tk.DISABLED)
        
        try:
            # Ejecutar análisis
            self.vulnerabilidades_detectadas = analizar_resultados_completos(self.resultados_finales)
            self.resumen_vulnerabilidades = obtener_resumen_vulnerabilidades(self.vulnerabilidades_detectadas)
            
            # Actualizar vista
            self.actualizar_vista_vulnerabilidades()
            self.actualizar_resumen_vulnerabilidades()
            
            self.log(f"✅ Análisis completado: {len(self.vulnerabilidades_detectadas)} vulnerabilidades detectadas")
            messagebox.showinfo(
                "Análisis Completado",
                f"Análisis de vulnerabilidades completado.\n\n"
                f"Total: {self.resumen_vulnerabilidades['total']}\n"
                f"Críticas: {self.resumen_vulnerabilidades['criticas']}\n"
                f"Altas: {self.resumen_vulnerabilidades['altas']}\n"
                f"Medias: {self.resumen_vulnerabilidades['medias']}\n"
                f"Bajas: {self.resumen_vulnerabilidades['bajas']}"
            )
        except Exception as e:
            self.log(f"❌ Error en análisis: {str(e)}")
            messagebox.showerror("Error", f"Error durante el análisis:\n{str(e)}")
        finally:
            self.btn_analizar.config(state=tk.NORMAL)
    
    def actualizar_vista_vulnerabilidades(self):
        """Actualiza la vista de vulnerabilidades en el Treeview"""
        # Limpiar vista actual
        for item in self.tree_vuln.get_children():
            self.tree_vuln.delete(item)
        
        if not self.vulnerabilidades_detectadas:
            return
        
        # Aplicar filtros
        vulnerabilidades_filtradas = self.vulnerabilidades_detectadas.copy()
        severidad_filtro = self.filter_severidad_var.get()
        estado_filtro = self.filter_estado_var.get()
        
        if severidad_filtro != "Todas":
            vulnerabilidades_filtradas = [v for v in vulnerabilidades_filtradas if v.get("severidad") == severidad_filtro]
        if estado_filtro != "Todos":
            vulnerabilidades_filtradas = [v for v in vulnerabilidades_filtradas if v.get("estado") == estado_filtro]
        
        # Agregar vulnerabilidades al treeview
        for idx, vuln in enumerate(vulnerabilidades_filtradas, 1):
            valores = (
                str(idx),
                vuln.get("ip", ""),
                vuln.get("puerto", ""),
                vuln.get("servicio", ""),
                vuln.get("severidad", ""),
                vuln.get("tipo", ""),
                vuln.get("descripcion", "")[:80] + "..." if len(vuln.get("descripcion", "")) > 80 else vuln.get("descripcion", ""),
                vuln.get("estado", "Pendiente")
            )
            item = self.tree_vuln.insert("", tk.END, values=valores)
            
            # Aplicar colores según severidad
            severidad = vuln.get("severidad", "")
            if severidad in COLORES_SEVERIDAD:
                color_hex = COLORES_SEVERIDAD[severidad]
                # Convertir hex a RGB
                r = int(color_hex[0:2], 16)
                g = int(color_hex[2:4], 16)
                b = int(color_hex[4:6], 16)
                color_rgb = f"#{color_hex}"
                self.tree_vuln.set(item, "Severidad", severidad)
    
    def actualizar_resumen_vulnerabilidades(self):
        """Actualiza el resumen estadístico de vulnerabilidades"""
        self.resumen_text.config(state=tk.NORMAL)
        self.resumen_text.delete("1.0", tk.END)
        
        if self.resumen_vulnerabilidades:
            resumen = self.resumen_vulnerabilidades
            texto = f"""📊 RESUMEN DE VULNERABILIDADES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ frame.rowconfigure(2, weight=1)
        
        # Título
        title = ttk.Label(
            frame,
            text="🤖 Análisis Avanzado de Vulnerabilidades con IA",
            font=("Arial", 14, "bold")
        )
        title.grid(row=0, column=0, pady=(0, 10))
        
        # Botones de acción
        action_frame = ttk.Frame(frame)
        action_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=10)
        
        self.btn_analizar = ttk.Button(
            action_frame,
            text="🔍 Analizar Vulnerabilidades",
            command=self.analizar_vulnerabilidades,
            style="Accent.TButton"
        )
        self.btn_analizar.grid(row=0, column=0, padx=5)
        
        self.btn_refrescar = ttk.Button(
            action_frame,
            text="🔄 Refrescar Vista",
            command=self.refrescar_vista_vulnerabilidades
        )
        self.btn_refrescar.grid(row=0, column=1, padx=5)
        
        # Resumen estadístico
        resumen_frame = ttk.LabelFrame(frame, text="Resumen de Vulnerabilidades", padding="10")
        resumen_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=10)
        resumen_frame.columnconfigure(0, weight=1)
        
        self.resumen_text = tk.Text(resumen_frame, height=4, wrap=tk.WORD, state=tk.DISABLED)
        self.resumen_text.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # Vista de vulnerabilidades con Treeview
        vuln_frame = ttk.LabelFrame(frame, text="Vulnerabilidades Detectadas", padding="10")
        vuln_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        vuln_frame.columnconfigure(0, weight=1)
        vuln_frame.rowconfigure(0, weight=1)
        frame.rowconfigure(3, weight=1)
        
        # Scrollbars
        scrollbar_y = ttk.Scrollbar(vuln_frame, orient=tk.VERTICAL)
        scrollbar_x = ttk.Scrollbar(vuln_frame, orient=tk.HORIZONTAL)
        
        # Treeview para mostrar vulnerabilidades
        columns = ("ID", "IP", "Puerto", "Servicio", "Severidad", "Tipo", "Descripción", "Estado")
        self.tree_vuln = ttk.Treeview(vuln_frame, columns=columns, show="headings", 
                                      yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)
        
        scrollbar_y.config(command=self.tree_vuln.yview)
        scrollbar_x.config(command=self.tree_vuln.xview)
        
        # Configurar columnas
        self.tree_vuln.heading("ID", text="ID")
        self.tree_vuln.heading("IP", text="IP")
        self.tree_vuln.heading("Puerto", text="Puerto")
        self.tree_vuln.heading("Servicio", text="Servicio")
        self.tree_vuln.heading("Severidad", text="Severidad")
        self.tree_vuln.heading("Tipo", text="Tipo")
        self.tree_vuln.heading("Descripción", text="Descripción")
        self.tree_vuln.heading("Estado", text="Estado")
        
        self.tree_vuln.column("ID", width=50)
        self.tree_vuln.column("IP", width=120)
        self.tree_vuln.column("Puerto", width=70)
        self.tree_vuln.column("Servicio", width=100)
        self.tree_vuln.column("Severidad", width=80)
        self.tree_vuln.column("Tipo", width=150)
        self.tree_vuln.column("Descripción", width=300)
        self.tree_vuln.column("Estado", width=120)
        
        self.tree_vuln.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        scrollbar_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Frame de acciones para vulnerabilidades seleccionadas
        action_vuln_frame = ttk.Frame(vuln_frame)
        action_vuln_frame.grid(row=2, column=0, columnspan=2, pady=10, sticky=(tk.W, tk.E))
        
        ttk.Label(action_vuln_frame, text="Acción para vulnerabilidad seleccionada:").grid(row=0, column=0, padx=5)
        
        self.btn_marcar_falso = ttk.Button(
            action_vuln_frame,
            text="❌ Marcar como Falso Positivo",
            command=self.marcar_falso_positivo
        )
        self.btn_marcar_falso.grid(row=0, column=1, padx=5)
        
        self.btn_marcar_verificado = ttk.Button(
            action_vuln_frame,
            text="✅ Marcar como Verificado",
            command=self.marcar_verificado
        )
        self.btn_marcar_verificado.grid(row=0, column=2, padx=5)
        
        self.btn_marcar_confirmado = ttk.Button(
            action_vuln_frame,
            text="🔴 Marcar como Confirmado",
            command=self.marcar_confirmado
        )
        self.btn_marcar_confirmado.grid(row=0, column=3, padx=5)
        
        # Filtros
        filter_frame = ttk.LabelFrame(frame, text="Filtros", padding="10")
        filter_frame.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Label(filter_frame, text="Severidad:").grid(row=0, column=0, padx=5)
        self.filter_severidad_var = tk.StringVar(value="Todas")
        filter_severidad = ttk.Combobox(
            filter_frame,
            textvariable=self.filter_severidad_var,
            values=["Todas", "Crítica", "Alta", "Media", "Baja"],
            state="readonly",
            width=15
        )
        filter_severidad.grid(row=0, column=1, padx=5)
        filter_severidad.bind("<<ComboboxSelected>>", lambda e: self.aplicar_filtros())
        
        ttk.Label(filter_frame, text="Estado:").grid(row=0, column=2, padx=5)
        self.filter_estado_var = tk.StringVar(value="Todos")
        filter_estado = ttk.Combobox(
            filter_frame,
            textvariable=self.filter_estado_var,
            values=["Todos", "Pendiente", "Verificado", "Falso Positivo", "Confirmado"],
            state="readonly",
            width=15
        )
        filter_estado.grid(row=0, column=3, padx=5)
        filter_estado.bind("<<ComboboxSelected>>", lambda e: self.aplicar_filtros())
        
        ttk.Button(
            filter_frame,
            text="🔍 Filtrar",
            command=self.aplicar_filtros
        ).grid(row=0, column=4, padx=5)
        
        ttk.Button(
            filter_frame,
            text="🔄 Limpiar Filtros",
            command=self.limpiar_filtros
        ).grid(row=0, column=5, padx=5)
    
    def log(self, mensaje: str):


def main():
    """Función principal para iniciar la GUI"""
    root = tk.Tk()
    app = VulnerabilitiesGUI(root)
    root.mainloop()


if __name__ == "__main__":
    import sys
    main()
