#📋 Instrucciones de Uso
#1. Hacer el Script Ejecutable

# Navegar al directorio del proyecto
cd /opt/zabbix-ibm-flash

# Hacer ejecutable el script
chmod +x scripts/install.sh


# Ejecución normal
sudo ./scripts/install.sh

# Ejecución forzada (reinstalar todo)
sudo ./scripts/install.sh -f

# Modo dry-run (solo simulación, sin cambios)
sudo ./scripts/install.sh -n

# Mostrar ayuda

sudo ./scripts/install.sh -h




# Verificar binario
ls -la /usr/lib/zabbix/externalscripts/ibm_flash_monitor

# Verificar configuración
ls -la /opt/zabbix-ibm-flash/config/

# Verificar logs
tail -f /opt/zabbix-ibm-flash/logs/ibm_flash_monitor.log

# Probar conexión
sudo -u zabbix /usr/lib/zabbix/externalscripts/ibm_flash_monitor <FLASHSYSTEM_IP> system_health