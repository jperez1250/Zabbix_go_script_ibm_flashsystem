# Guía de Instalación - IBM FlashSystem Monitor para Zabbix 7.2

## Requisitos Previos

| Componente | Versión Mínima | Notas |
|------------|---------------|-------|
| **Sistema Operativo** | Red Hat 9 / AlmaLinux 9 | SELinux Enforcing soportado |
| **Zabbix Server** | 7.2 | Instalado desde paquetes (no Docker) |
| **Go** | 1.22+ | Solo para compilación (no runtime) |
| **IBM FlashSystem** | Storage Virtualize V8.7 | FS5045, FS7300, FS9500, SVC |
| **SSH** | OpenSSH 8.0+ | Con soporte ED25519 |

## Paso 1: Preparar el Entorno

### 1.1 Instalar Dependencias

```bash
# Actualizar sistema
sudo dnf update -y

# Instalar Go (si no está instalado)
sudo dnf install -y golang git

# Verificar instalación
go version
# Esperado: go version go1.22.x linux/amd64


# Crear directorios del proyecto
sudo mkdir -p /opt/zabbix-ibm-flash/{bin,config,logs,templates,src/lib}
sudo mkdir -p /usr/lib/zabbix/externalscripts

# Establecer permisos base
sudo chmod 750 /opt/zabbix-ibm-flash
sudo chown -R zabbix:zabbix /opt/zabbix-ibm-flash


#Paso 2: Clonar y Compilar el Proyecto
#2.1 Clonar Repositorio

# Navegar al directorio de código
cd /opt/zabbix-ibm-flash/src

# Clonar repositorio (o copiar archivos)
git clone https://github.com/tu-usuario/zabbix-ibm-flashsystem-monitor.git .

# Inicializar módulo Go
go mod init zabbix-ibm-flash

# Descargar dependencias
go mod tidy
go mod download

# Compilar binario estático para Linux amd64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ibm_flash_monitor .

# Verificar binario
file ibm_flash_monitor
# Esperado: ELF 64-bit LSB executable, x86-64, statically linked

# Copiar binario a ruta de ExternalScripts de Zabbix
sudo cp ibm_flash_monitor /usr/lib/zabbix/externalscripts/

# Establecer permisos seguros
sudo chown zabbix:zabbix /usr/lib/zabbix/externalscripts/ibm_flash_monitor
sudo chmod 750 /usr/lib/zabbix/externalscripts/ibm_flash_monitor

# Verificar permisos
ls -la /usr/lib/zabbix/externalscripts/ibm_flash_monitor
# Esperado: -rwxr-x--- zabbix zabbix

#Paso 3: Configurar Archivos de Configuración
#3.1 Crear zabbix.json

# Copiar desde plantilla
sudo cp /opt/zabbix-ibm-flash/config/zabbix.json.example \
        /opt/zabbix-ibm-flash/config/zabbix.json

# Establecer permisos
sudo chown root:zabbix /opt/zabbix-ibm-flash/config/zabbix.json
sudo chmod 640 /opt/zabbix-ibm-flash/config/zabbix.json

# Editar si es necesario (opcional - defaults funcionan)
sudo vi /opt/zabbix-ibm-flash/config/zabbix.json

#3.2 Crear secrets.env

# Copiar desde plantilla
sudo cp /opt/zabbix-ibm-flash/config/secrets.env.example \
        /opt/zabbix-ibm-flash/config/secrets.env

# Establecer permisos RESTRINGIDOS
sudo chown root:zabbix /opt/zabbix-ibm-flash/config/secrets.env
sudo chmod 600 /opt/zabbix-ibm-flash/config/secrets.env

# Editar con valores reales
sudo vi /opt/zabbix-ibm-flash/config/secrets.env

#3.3 Generar Clave SSH ED25519

# Generar par de claves como usuario zabbix
sudo -u zabbix ssh-keygen -t ed25519 \
  -f /opt/zabbix-ibm-flash/config/id_ibm_flash \
  -N "" \
  -C "zabbix@alatreon-bank-ibm-flash"

# Verificar permisos (DEBE ser 600)
sudo chmod 600 /opt/zabbix-ibm-flash/config/id_ibm_flash
sudo chown zabbix:zabbix /opt/zabbix-ibm-flash/config/id_ibm_flash

# Verificar clave
ssh-keygen -l -f /opt/zabbix-ibm-flash/config/id_ibm_flash.pub
# Esperado: 256 SHA256:xxxxx zabbix@alatreon-bank-ibm-flash (ED25519)


# Opción A: Usar ssh-copy-id
sudo -u zabbix ssh-copy-id -i /opt/zabbix-ibm-flash/config/id_ibm_flash.pub \
  zabbix_monitor@<flashsystem_management_ip>

# Opción B: Copiar manualmente
# 1. Mostrar contenido de clave pública
cat /opt/zabbix-ibm-flash/config/id_ibm_flash.pub

# 2. Conectarse al FlashSystem como superuser
ssh superuser@<flashsystem_management_ip>

# 3. Ejecutar comando CLI para agregar clave
# chuser -ssh_key "<pegar_contenido_clave_pública>" zabbix_monitor


# Conectarse al FlashSystem
ssh superuser@<flashsystem_management_ip>

# Verificar configuración del usuario
lsuser -name zabbix_monitor -delim :

# Esperado (campos relevantes):
# ssh_key=yes
# securityadmin=no  (solo lectura)
# webui=no          (sin acceso GUI)
# usergrp_id=4      (grupo Monitor)


#Paso 4: Configurar SELinux (Red Hat 9)

# Verificar estado
getenforce
# Esperado: Enforcing

# Verificar contexto del directorio
ls -Z /usr/lib/zabbix/externalscripts/
# Esperado: system_u:object_r:zabbix_script_t:s0

# Restaurar contexto SELinux para ExternalScripts
sudo restorecon -v /usr/lib/zabbix/externalscripts/ibm_flash_monitor

# Permitir conexión SSH saliente desde proceso zabbix
sudo setsebool -P zabbix_can_network on

# Permitir lectura de archivos de configuración
sudo semanage fcontext -a -t zabbix_var_run_t "/opt/zabbix-ibm-flash/config(/.*)?"
sudo restorecon -Rv /opt/zabbix-ibm-flash/config

# Permitir escritura de logs
sudo semanage fcontext -a -t zabbix_log_t "/opt/zabbix-ibm-flash/logs(/.*)?"
sudo restorecon -Rv /opt/zabbix-ibm-flash/logs

# Verificar políticas aplicadas
semanage fcontext -l | grep zabbix-ibm
getsebool -a | grep zabbix

# Verificar contexto del binario
ls -Z /usr/lib/zabbix/externalscripts/ibm_flash_monitor
# Esperado: system_u:object_r:zabbix_script_t:s0

# Si hay problemas, verificar logs de auditoría
sudo grep ibm_flash_monitor /var/log/audit/audit.log | audit2why


#Paso 5: Configurar Zabbix Server

# Verificar ruta de ExternalScripts en zabbix_server.conf
grep "^ExternalScripts=" /etc/zabbix/zabbix_server.conf
# Esperado: ExternalScripts=/usr/lib/zabbix/externalscripts

# Verificar Timeout (debe ser >= 30s)
grep "^Timeout=" /etc/zabbix/zabbix_server.conf
# Esperado: Timeout=30

# Si necesita cambiar, editar y reiniciar:
sudo vi /etc/zabbix/zabbix_server.conf
sudo systemctl restart zabbix-server


# Validar configuración
sudo zabbix_server -T
# Esperado: configuration file is valid

# Recargar configuración sin reiniciar
sudo zabbix_server -R config_cache_reload

#Paso 6: Importar Plantilla Zabbix

1. Navegar a: Data Collection → Templates
2. Click en: Import
3. Seleccionar archivo: templates/zabbix_template_ibm_flashsystem_5045.yaml
4. Click en: Import
5. Verificar mensaje de éxito

#Paso 7: Crear Host en Zabbix
1. Navegar a: Data Collection → Hosts
2. Click en: Create host
3. Completar campos:
   - Host name: IBM-FlashSystem-5045-<Serial>
   - Visible name: IBM FlashSystem 5045 Production
   - Groups: Templates/IBM Storage
   - Interfaces: SNMP (IP de gestión del FlashSystem)
4. Click en: Add

1. En el host creado, ir a: Templates tab
2. Click en: Select
3. Buscar: IBM FlashSystem 5045 by Go ExternalCheck
4. Click en: Add
5. Click en: Update


# Configurar Macros

Macro
	
Valor
	
Descripción
{$IBM_STORAGE.SSH_USER}
	
zabbix_monitor
	
Usuario de solo lectura
{$IBM_STORAGE.SSH_KEY_PATH}
	
/opt/zabbix-ibm-flash/config/id_ibm_flash
	
Ruta clave SSH
{$IBM_STORAGE.TIMEOUT}
	
25
	
Timeout SSH (segundos)
{$IBM_STORAGE.LLD_INTERVAL}
	
3600
	
Intervalo LLD (segundos)
{$POOL_CAPACITY_WARN}
	
85
	
Umbral warning capacidad (%)
{$POOL_CAPACITY_CRIT}
	
95
	
Umbral crítico capacidad (%)

#Paso 8: Pruebas de Validación
# Ejecutar como usuario zabbix
sudo -u zabbix /usr/lib/zabbix/externalscripts/ibm_flash_monitor \
  <flashsystem_ip> \
  system_health

# Esperado: "1" (online) o "0" (offline)

# Probar descubrimiento LLD
sudo -u zabbix /usr/lib/zabbix/externalscripts/ibm_flash_monitor \
  <flashsystem_ip> \
  discover_pools

# Esperado: JSON {"data":[{...},...]}

#Verificar en Zabbix Frontend


1. Navegar a: Monitoring → Latest Data
2. Seleccionar host: IBM-FlashSystem-5045-<Serial>
3. Verificar items con datos (no "Not supported")
4. Esperar ciclo LLD (1 hora) para items descubiertos



# Verificar logs del script
sudo tail -f /opt/zabbix-ibm-flash/logs/ibm_flash_monitor.log

# Verificar logs de Zabbix Server
sudo tail -f /var/log/zabbix/zabbix_server.log | grep -i "external\|ibm"

# Verificar errores de SELinux
sudo grep ibm_flash_monitor /var/log/audit/audit.log | audit2why



1. Navegar a: Monitoring → Problems
2. Verificar triggers evaluándose
3. Simular problema (ej: pool > 85%) para verificar alerta


# Troubleshooting Común



# 1. Verificar permisos del binario
ls -la /usr/lib/zabbix/externalscripts/ibm_flash_monitor
# Esperado: -rwxr-x--- zabbix:zabbix

# 2. Verificar permisos de clave SSH
stat -c '%a %U:%G' /opt/zabbix-ibm-flash/config/id_ibm_flash
# Esperado: 600 zabbix:zabbix

# 3. Probar conexión SSH manualmente
sudo -u zabbix ssh -i /opt/zabbix-ibm-flash/config/id_ibm_flash \
  zabbix_monitor@<flashsystem_ip> "lssystem"

# 4. Verificar logs del script
sudo tail -100 /opt/zabbix-ibm-flash/logs/ibm_flash_monitor.log



# 1. Aumentar timeout en zabbix_server.conf
sudo vi /etc/zabbix/zabbix_server.conf
# Timeout=30

# 2. Reiniciar Zabbix Server
sudo systemctl restart zabbix-server

# 3. Verificar tiempo de ejecución del script
time sudo -u zabbix /usr/lib/zabbix/externalscripts/ibm_flash_monitor \
  <flashsystem_ip> system_health
# Debe completar en <30s


# 1. Verificar denegaciones
sudo grep ibm_flash_monitor /var/log/audit/audit.log

# 2. Generar política desde denegaciones
sudo grep ibm_flash_monitor /var/log/audit/audit.log | audit2allow -M ibm_flash

# 3. Instalar política
sudo semodule -i ibm_flash.pp

# 4. Restaurar contextos
sudo restorecon -Rv /opt/zabbix-ibm-flash
sudo restorecon -v /usr/lib/zabbix/externalscripts/ibm_flash_monitor



# 1. Verificar output del comando LLD
sudo -u zabbix /usr/lib/zabbix/externalscripts/ibm_flash_monitor \
  <flashsystem_ip> discover_pools | jq .

# 2. Verificar intervalo LLD en template
# Debe ser >= 3600s para no sobrecargar storage

# 3. Forzar ejecución de LLD
# Monitoring → Latest Data → Executar ahora (icono de refresh)

# 4. Verificar logs de LLD
sudo grep -i "lld\|discovery" /var/log/zabbix/zabbix_server.log



#Paso 10: Mantenimiento

# Ejecutar script de rotación
sudo /opt/zabbix-ibm-flash/scripts/rotate_ssh_key.sh

# O manualmente:
# 1. Generar nueva clave
# 2. Instalar en FlashSystem
# 3. Verificar conexión
# 4. Reemplazar clave antigua
# 5. Eliminar backup después de 30 días




# 1. Detener temporalmente polling (Maintenance mode)
# 2. Compilar nuevo binario
# 3. Backup del binario actual
sudo cp /usr/lib/zabbix/externalscripts/ibm_flash_monitor \
        /usr/lib/zabbix/externalscripts/ibm_flash_monitor.backup
# 4. Copiar nuevo binario
sudo cp src/ibm_flash_monitor /usr/lib/zabbix/externalscripts/
# 5. Verificar permisos
sudo chown zabbix:zabbix /usr/lib/zabbix/externalscripts/ibm_flash_monitor
sudo chmod 750 /usr/lib/zabbix/externalscripts/ibm_flash_monitor
# 6. Probar manualmente
sudo -u zabbix /usr/lib/zabbix/externalscripts/ibm_flash_monitor <ip> system_health
# 7. Habilitar polling





# Crear backup de configuración
sudo tar -czvf /backup/zabbix-ibm-flash-config-$(date +%Y%m%d).tar.gz \
  /opt/zabbix-ibm-flash/config/ \
  /opt/zabbix-ibm-flash/templates/

# Verificar backup
tar -tzf /backup/zabbix-ibm-flash-config-$(date +%Y%m%d).tar.gz


Referencias Documentales
Documento
	
Versión
	
URL/Referencia
IBM Storage Virtualize V8.7 Redbook
	
SG24-8561
	
sg248561.txt
IBM CLI Command Reference
	
V8.7
	
svc_bkmap_cliguidebk (1).txt
IBM Data Reduction & Replication
	
SG24-8543
	
sg248543.txt
Zabbix 7.2 Documentation
	
7.2
	
Zabbix_Documentation_7.2.en.txt
Checklist de Instalación
Ítem
	
Estado
	
Verificación
Go instalado
	
☐
	
go version
Binario compilado
	
☐
	
file ibm_flash_monitor
Binario en ExternalScripts
	
☐
	
ls -la /usr/lib/zabbix/externalscripts/
Permisos correctos
	
☐
	
stat -c '%a %U:%G'
Clave SSH generada
	
☐
	
ssh-keygen -l -f id_ibm_flash.pub
Clave instalada en FlashSystem
	
☐
	
lsuser -name zabbix_monitor
SELinux configurado
	
☐
	
getenforce, ls -Z
zabbix.json creado
	
☐
	
ls -la config/zabbix.json
secrets.env creado
	
☐
	
ls -la config/secrets.env
Plantilla importada
	
☐
	
Frontend Zabbix
Host creado
	
☐
	
Frontend Zabbix
Items con datos
	
☐
	
Monitoring → Latest Data
Triggers activos
	
☐
	
Monitoring → Problems