#NO PROBADO, EN DESARROLLO
# Zabbix_go_script_ibm_flashsystem
 monitoreo script ibm flashsystem
# Zabbix IBM FlashSystem Monitor

[![Go Build](https://github.com/yourusername/zabbix-ibm-flashsystem-monitor/actions/workflows/go-build.yml/badge.svg)](https://github.com/yourusername/zabbix-ibm-flashsystem-monitor/actions/workflows/go-build.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Zabbix Version](https://img.shields.io/badge/Zabbix-7.2-green.svg)](https://www.zabbix.com/documentation/7.2)
[![IBM Storage](https://img.shields.io/badge/IBM-Storage%20Virtualize%20V8.7-red.svg)](https://www.ibm.com/products/storage-virtualize)

Monitor seguro para IBM FlashSystem 5045/7300/9500 y SAN Volume Controller usando Zabbix 7.2 ExternalCheck con autenticación SSH basada en claves.

## 🎯 Características

- ✅ **Seguridad Primero**: Autenticación SSH con claves ED25519 (sin passwords)
- ✅ **Zabbix 7.2 Compatible**: ExternalCheck nativo con Low-Level Discovery
- ✅ **IBM Storage Virtualize V8.7**: Soporte completo para CLI commands
- ✅ **Métricas Críticas**:
  - Safeguarded Copy status y expiración
  - Capacidad de pools (%, bytes libres, compresión)
  - Estado de replicación (HyperSwap, Remote Copy)
  - Hardware health (drives, baterías, PSUs, enclosures)
  - Eventos críticos del sistema
- ✅ **Red Hat 9 Optimizado**: SELinux policies incluidas
- ✅ **Despliegue Flexible**: Scripts bash, Ansible, o manual

## 📋 Requisitos Previos

| Componente | Versión Mínima | Notas |
|------------|---------------|-------|
| **Zabbix Server** | 7.2 | Instalado desde paquetes (no Docker) |
| **Sistema Operativo** | Red Hat 9 / AlmaLinux 9 | SELinux Enforcing soportado |
| **IBM FlashSystem** | Storage Virtualize V8.7 | FS5045, FS7300, FS9500, SVC |
| **Go (compilación)** | 1.22+ | Solo para compilar, no para runtime |
| **SSH** | OpenSSH 8.0+ | Con soporte ED25519 |

## 🚀 Instalación Rápida

### Opción 1: Instalación Automática (Recomendada)

```bash
# Clonar repositorio
git clone https://github.com/yourusername/zabbix-ibm-flashsystem-monitor.git
cd zabbix-ibm-flashsystem-monitor

# Ejecutar script de instalación
sudo ./scripts/install.sh

# El script:
# 1. Compila el binario Go
# 2. Configura permisos y SELinux
# 3. Genera claves SSH
# 4. Instala plantilla Zabbix
# 5. Valida la configuración
