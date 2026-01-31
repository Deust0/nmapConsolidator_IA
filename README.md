# Gestor Profesional de Vulnerabilidades v10.0

Herramienta profesional para la gestión y análisis de vulnerabilidades basada en resultados de escaneos Nmap. Incluye escaneos automáticos, procesamiento de múltiples formatos de salida y generación de informes Excel completos.

## 🆕 Novedades v10.0

- **Interfaz Gráfica (GUI)**: Interfaz moderna con 3 fases de trabajo
- **Escaneos Automáticos**: Ejecución automática de escaneos Nmap desde la aplicación
- **Fase 1 - Discovery**: Escaneo inicial para descubrir puertos abiertos
- **Fase 2 - Versiones**: Escaneo de versiones en puertos descubiertos
- **Fase 3 - Excel Final**: Generación de informe Excel consolidado
- **Procesamiento Paralelo**: Escaneos simultáneos con control de threads
- **Modo CLI**: Sigue disponible para automatización y scripts

## 📋 Características

### Funcionalidades Principales

- ✅ Procesamiento de archivos `.gnmap`, `.nmap` y `.xml` de Nmap
- ✅ Extracción de dominios completos (solo desde `.nmap` y `.xml`)
- ✅ Deduplicación y consolidación de resultados
- ✅ Generación de informes Excel profesionales con múltiples hojas
- ✅ Escaneos automáticos de discovery y versiones
- ✅ Interfaz gráfica intuitiva con progreso en tiempo real
- ✅ Generación de scripts Nmap ejecutables
- ✅ Scope para testssl.sh

### Hojas del Excel

1. **Resultados Consolidados**: Todos los puertos y servicios encontrados
2. **Dashboard Vulnerabilidades**: Gráficos y estadísticas
3. **Resumen por IP**: Resumen de cada host
4. **Seguimiento Vulnerabilidades**: Gestión de hallazgos
5. **Matriz de Riesgos**: Análisis de riesgo por severidad
6. **Análisis por IP**: Estadísticas detalladas por host
7. **Comandos Nmap Inteligentes**: Comandos sugeridos para cada puerto
8. **Info Escaneos**: Información de archivos procesados
9. **Instrucciones**: Guía de uso

## 🚀 Instalación

### Requisitos

- Python 3.7 o superior
- Nmap instalado y en el PATH
- Librerías Python:
  ```bash
  pip install openpyxl
  ```

### Instalación de Nmap

- **Windows**: Descargar desde [nmap.org](https://nmap.org/download.html)
- **Linux**: `sudo apt-get install nmap` (Debian/Ubuntu) o `sudo yum install nmap` (RHEL/CentOS)
- **macOS**: `brew install nmap`

## 📖 Uso

### Modo GUI (Recomendado)

```bash
python main.py
# o
python main.py --gui
```

La interfaz gráfica presenta 3 fases:

#### Fase 1: Discovery
1. Ingresa las IPs o rangos a escanear (una por línea)
2. Selecciona opciones de puertos (top-ports, rango, o lista específica)
3. Configura el número de threads paralelos
4. Haz clic en "Iniciar Escaneo Discovery"

#### Fase 2: Versiones
1. Selecciona la carpeta con los resultados de discovery
2. Haz clic en "Procesar Discovery y Escanear Versiones"
3. El sistema procesará los archivos y ejecutará escaneos de versión automáticamente

#### Fase 3: Excel Final
1. Selecciona la carpeta con todos los resultados
2. Haz clic en "Generar Excel Final"
3. El Excel se generará con todos los resultados consolidados

### Modo CLI (Línea de Comandos)

```bash
python main.py --cli
```

El modo CLI procesa archivos existentes de Nmap y genera el Excel:

1. Ingresa la ruta de los archivos `.gnmap`, `.nmap` y `.xml`
2. El sistema procesará y generará el Excel automáticamente

## 📁 Estructura del Proyecto

```
nmapconsolidator/
├── main.py                 # Punto de entrada principal
├── gui.py                  # Interfaz gráfica
├── nmap_scanner.py         # Módulo de escaneos automáticos
├── config.py               # Configuraciones y constantes
├── file_finders.py          # Búsqueda de archivos
├── parsers.py              # Parsing de archivos Nmap
├── data_processor.py       # Procesamiento y deduplicación
├── nmap_commands.py        # Generación de comandos Nmap
├── excel_generator.py      # Generación de hojas Excel
├── file_writers.py         # Escritura de archivos de salida
└── README.md               # Este archivo
```

## 🔧 Configuración

### Puertos SSL/TLS Recomendados

Los puertos SSL/TLS se configuran en `config.py`:
- 443, 8443, 9443 (HTTPS)
- 993, 995 (IMAPS, POP3S)
- 465, 587, 25 (SMTPS/STARTTLS)
- Y más...

### Scripts Nmap por Puerto

Los scripts Nmap recomendados por puerto se configuran en `config.py` en `SCRIPTS_POR_PUERTO`.

## 📊 Formato de Salida

### Archivos Generados

- `auditoria_[identificador].xlsx`: Excel completo con todas las hojas
- `alcance_[identificador].txt`: Lista de IPs con puertos abiertos
- `scope_testssl_[identificador].txt`: Scope para testssl.sh
- `nmap_scripts/`: Scripts bash ejecutables por IP

### Identificador

El identificador se genera automáticamente con el formato:
```
consolidado_[num_hosts]hosts_[num_scans]scans_[timestamp]
```

## ⚙️ Opciones de Escaneo

### Discovery
- **Top Ports**: `--top-ports 100` o `--top-ports 1000`
- **Rango**: `1-65535` o `80-443`
- **Lista específica**: `80,443,22,21,25`

### Versiones
- Escaneos automáticos con scripts específicos por puerto
- Detección de versiones con `-sV`
- Scripts Nmap no intrusivos según el puerto

## 🛠️ Desarrollo

### Estructura Modular

El proyecto está completamente modularizado:
- Cada función tiene su propio módulo
- Fácil mantenimiento y extensión
- Separación clara de responsabilidades

### Agregar Nuevas Funcionalidades

1. **Nuevos parsers**: Agregar funciones en `parsers.py`
2. **Nuevas hojas Excel**: Agregar funciones en `excel_generator.py`
3. **Nuevos tipos de escaneo**: Extender `nmap_scanner.py`

## 📝 Notas

- Los hostnames se extraen **solo** de archivos `.nmap` y `.xml`
- Los hostnames de `.gnmap` se ignoran (suelen estar incompletos)
- Los escaneos se ejecutan con parámetros no intrusivos por defecto
- El número de threads paralelos es configurable (por defecto: 5)

## 🐛 Solución de Problemas

### Nmap no encontrado
- Verifica que Nmap esté instalado: `nmap --version`
- Asegúrate de que Nmap esté en el PATH del sistema

### Errores de permisos
- En Linux/macOS, algunos escaneos pueden requerir permisos de root
- Considera usar `sudo` si es necesario

### Timeouts en escaneos
- Aumenta el timeout en `nmap_scanner.py` si es necesario
- Reduce el número de threads si hay problemas de red

## 📄 Licencia

Este proyecto es de código abierto. Úsalo responsablemente y solo en sistemas que tengas autorización para escanear.

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor:
1. Fork el proyecto
2. Crea una rama para tu feature
3. Commit tus cambios
4. Push a la rama
5. Abre un Pull Request

---

**Versión**: 10.0  
**Última actualización**: 2024
