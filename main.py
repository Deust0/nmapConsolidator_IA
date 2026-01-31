"""
Punto de entrada principal del Gestor de Vulnerabilidades
Versión 10.0 - Modular con GUI y Escaneos Automáticos
"""

import os
import sys


def main_cli():
    """Modo de línea de comandos (CLI)"""
    from file_finders import buscar_archivos_gnmap, buscar_archivos_nmap, buscar_archivos_xml
    from data_processor import (
        procesar_multiples_gnmap, procesar_multiples_nmap, procesar_multiples_xml,
        deduplicar_y_combinar, generar_identificador
    )
    from file_writers import (
        guardar_xlsx_completo, guardar_scripts_ejecutables,
        guardar_alcance, generar_scope_testssl
    )
    
    print("=" * 80)
    print("  GESTOR PROFESIONAL DE VULNERABILIDADES - VERSIÓN 10.0")
    print("  ✓ Columna 'Hostnames/Dominios' añadida")
    print("  ✓ Captura dominios completos SOLO desde .nmap y .xml")
    print("  ✓ NO usa hostnames de .gnmap (incompletos)")
    print("=" * 80)
    print()
    
    ruta = input("Ingresa la ruta de los archivos .gnmap, .nmap y XML (Enter para carpeta actual): ").strip()
    
    archivos_gnmap = buscar_archivos_gnmap(ruta if ruta else None)
    archivos_nmap = buscar_archivos_nmap(ruta if ruta else None)
    archivos_xml = buscar_archivos_xml(ruta if ruta else None)
    
    if not archivos_gnmap and not archivos_nmap and not archivos_xml:
        print("⚠ No se encontraron archivos .gnmap, .nmap ni XML.")
        sys.exit(1)
    
    print("\n🔄 Procesando archivos...")
    
    resultados_gnmap, ips_gnmap = procesar_multiples_gnmap(archivos_gnmap)
    resultados_nmap, ips_nmap = procesar_multiples_nmap(archivos_nmap)
    resultados_xml = procesar_multiples_xml(archivos_xml)
    
    # Combinar todas las IPs
    todas_ips = list(set(ips_gnmap + ips_nmap))
    
    resultados = deduplicar_y_combinar(resultados_gnmap, resultados_xml, resultados_nmap)
    identificador = generar_identificador(todas_ips, len(archivos_gnmap) + len(archivos_nmap) + len(archivos_xml))
    
    if resultados:
        print(f"\n📊 Resultados:")
        print(f"   - Hosts: {len(todas_ips)}")
        print(f"   - Puertos abiertos: {len(resultados)}")
        
        carpeta = f"resultados_{identificador}"
        os.makedirs(carpeta, exist_ok=True)
        
        archivos_todos = archivos_gnmap + archivos_nmap + archivos_xml
        guardar_xlsx_completo(resultados, identificador, archivos_todos, vulnerabilidades_ia=None)
        
        carpeta_scripts = os.path.join(carpeta, "nmap_scripts")
        guardar_scripts_ejecutables(resultados, carpeta_scripts)
        
        guardar_alcance(todas_ips, identificador, carpeta)
        generar_scope_testssl(resultados, identificador, carpeta_base="resultados")
        
        print(f"\n✅ Completado exitosamente")
        print(f"📁 Resultados: {carpeta}")
    else:
        print("⚠ No hay datos para procesar.")


def main_gui():
    """Modo de interfaz gráfica (GUI)"""
    from gui import main as gui_main
    gui_main()


def main():
    """Función principal que decide el modo de ejecución"""
    # Verificar argumentos de línea de comandos
    if len(sys.argv) > 1:
        if sys.argv[1] == "--gui" or sys.argv[1] == "-g":
            main_gui()
        elif sys.argv[1] == "--cli" or sys.argv[1] == "-c":
            main_cli()
        elif sys.argv[1] == "--help" or sys.argv[1] == "-h":
            print("Gestor Profesional de Vulnerabilidades v10.0")
            print("\nUso:")
            print("  python main.py          # Inicia en modo GUI")
            print("  python main.py --gui    # Inicia en modo GUI")
            print("  python main.py --cli    # Inicia en modo CLI")
            print("  python main.py --help   # Muestra esta ayuda")
            sys.exit(0)
        else:
            print(f"Opción desconocida: {sys.argv[1]}")
            print("Usa --help para ver las opciones disponibles")
            sys.exit(1)
    else:
        # Por defecto, iniciar GUI
        main_gui()


if __name__ == "__main__":
    main()
