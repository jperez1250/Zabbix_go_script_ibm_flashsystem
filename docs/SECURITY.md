
---

## 2. `docs/SECURITY.md` - Documentación de Seguridad

```markdown
# Política de Seguridad - IBM FlashSystem Monitor

## Principios de Seguridad

### 1. Mínimo Privilegio

- **Usuario de monitoreo:** `zabbix_monitor` con permisos de **solo lectura**
- **Sin acceso GUI:** `webui=no`
- **Sin privilegios administrativos:** `securityadmin=no`
- **Referencia:** sg248561.txt Capítulo 4 - User security best practices

### 2. Autenticación Segura

- **SSH Key-based:** ED25519 (sin password)
- **Sin password en texto plano:** Nunca almacenar credenciales en código
- **Permisos de clave:** 600 (rw-------)
- **Referencia:** svc_bkmap_cliguidebk (1).txt - SSH key management

### 3. Defensa en Profundidad

| Capa | Control | Implementación |
|------|---------|----------------|
| **Red** | VLAN de gestión separada | Firewall, ACLs |
| **Transporte** | SSH cifrado | ED25519, AES-256-GCM |
| **Autenticación** | Key-based | Sin password |
| **Autorización** | Whitelist de comandos | cli_commands.go |
| **Auditoría** | Logging completo | security.go |

## Gestión de Credenciales

### Claves SSH

```bash
# Generación (solo administrador)
sudo -u zabbix ssh-keygen -t ed25519 -f /opt/zabbix-ibm-flash/config/id_ibm_flash -N ""

# Permisos requeridos
chmod 600 /opt/zabbix-ibm-flash/config/id_ibm_flash
chown zabbix:zabbix /opt/zabbix-ibm-flash/config/id_ibm_flash

# Rotación (anual)
/opt/zabbix-ibm-flash/scripts/rotate_ssh_key.sh





Archivos de Configuración
Archivo
	
Permisos
	
Propietario
	
Contiene
zabbix.json
	
640
	
root:zabbix
	
Configuración no sensible
secrets.env
	
600
	
root:zabbix
	
Rutas de claves, NO passwords
id_ibm_flash
	
600
	
zabbix:zabbix
	
Clave privada SSH
known_hosts
	
644
	
zabbix:zabbix
	
Host keys verificados




## Whitelist de Comandos
## Comandos Permitidos (Solo Lectura)

// lib/cli_commands.go
var AllowedCommands = map[string]bool{
    // System
    "lssystem": true, "lsnode": true, "lsnodecanister": true,
    
    // Storage Pools
    "lsmdiskgrp": true, "lsmdisk": true, "lsfreeextents": true,
    
    // Volumes
    "lsvdisk": true, "lsvdiskcopy": true, "lsvolumegroup": true,
    
    // Hardware
    "lsdrive": true, "lsenclosure": true, "lsenclosurebattery": true,
    "lsenclosurecanister": true, "lsenclosurepsu": true,
    
    // Replication
    "lsreplication": true, "lsrcrelationship": true,
    
    // Safeguarded Copy
    "lssafeguardedcopy": true, "lssnapshot": true, "lssnapshotpolicy": true,
    
    // Events
    "lseventlog": true, "lsportstats": true,
}





#Comandos RECHAZADOS (Modificación)
❌ mk* (crear)
❌ rm* (eliminar)
❌ ch* (modificar) - excepto configuraciones específicas
❌ svctask* (tareas administrativas) 


// lib/cli_commands.go
#var DangerousCharsPattern = regexp.MustCompile(`[;|&$` + "`" + `><\n\r\\'"{}()\[\]]`)

### Logging y Auditoría

fff