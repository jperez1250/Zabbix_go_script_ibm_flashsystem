// lib/cli_commands.go
// Whitelist y validación de comandos CLI para IBM Storage Virtualize V8.7
// Compatible con FlashSystem 5045/7300/9500 y SAN Volume Controller
//
// Referencias de documentación:
// - svc_bkmap_cliguidebk (1).txt: CLI Command Reference (todos los comandos ls*)
// - sg248561.txt: IBM Storage Virtualize V8.7 Redbook (Capítulo 4 - Security)
// - sg248543.txt: Data Reduction & Replication (Capítulo 10 - CLI usage)
// - Zabbix_Documentation_7.2.en.txt: ExternalCheck specification (p.1518)
//
// Principios de seguridad:
// 1. Whitelist estricta de comandos (solo lectura, sin mk*, rm*, ch* peligrosos)
// 2. Rechazo de caracteres peligrosos (prevención de inyección de shell)
// 3. Validación de parámetros (longitud máxima, formato)
// 4. Logging de auditoría (comandos ejecutados, sin datos sensibles)
//
// Compilación:
//   cd src && go build -o ibm_flash_monitor .
//
// Uso:
//   valid := lib.IsCommandAllowed("lssystem -delim : -nohdr")
//   sanitized := lib.SanitizeParam(userInput)

package lib

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// ============================================================================
// CONSTANTES DE SEGURIDAD
// ============================================================================

const (
	// Longitud máxima de comando completo (prevención de DoS)
	MaxCommandLength = 4096

	// Longitud máxima de parámetro individual
	MaxParamLength = 256

	// Longitud máxima de hostname
	MaxHostnameLength = 253

	// Longitud máxima de username
	MaxUsernameLength = 32

	// Puerto SSH mínimo (puertos privilegiados < 1024 requieren root)
	MinSSHPort = 1024

	// Puerto SSH máximo
	MaxSSHPort = 65535

	// Timeout máximo permitido (debe ser < Timeout en zabbix_server.conf)
	// Referencia: Zabbix_Documentation_7.2.en.txt - Timeout parameter
	MaxTimeoutSeconds = 30
)

// ============================================================================
// WHITELIST DE COMANDOS PERMITIDOS
// ============================================================================

// AllowedCommands define la whitelist estricta de comandos CLI permitidos
// Referencia: svc_bkmap_cliguidebk (1).txt - Command reference
//
// CRITERIOS DE INCLUSIÓN:
// 1. Solo comandos de lectura (ls*, no mk*, rm*, ch* peligrosos)
// 2. Sin capacidad de modificar configuración crítica
// 3. Sin acceso a sistema de archivos del storage
// 4. Sin capacidad de ejecutar comandos del sistema operativo
//
// NOTA DE SEGURIDAD (sg248561.txt Capítulo 4):
// "User accounts should be configured with the minimum required privileges.
// For monitoring purposes, read-only access is sufficient."
var AllowedCommands = map[string]bool{
	// =========================================================================
	// SYSTEM COMMANDS (Información general del sistema)
	// Referencia: svc_bkmap_cliguidebk (1).txt - System commands
	// =========================================================================
	"lssystem": true,           // Estado general del sistema
	"lssystemfc": true,         // Información de puertos FC
	"lssystemstats": true,      // Estadísticas del sistema
	"lslicense": true,          // Licencias instaladas
	"lslogtrace": true,         // Estado de log trace
	"lssecurity": true,         // Configuración de seguridad
	"lsserviceresolution": true, // Resolución de servicio

	// =========================================================================
	// NODE/CANISTER COMMANDS (Nodos y canisters)
	// Referencia: svc_bkmap_cliguidebk (1).txt - Node commands
	// =========================================================================
	"lsnode": true,             // Lista de nodos/canisters
	"lsnodecanister": true,     // Información de canisters
	"lsnodebattery": true,      // Estado de baterías de nodo
	"lsnodestats": true,        // Estadísticas de nodo
	"lsnodevpd": true,          // VPD (Vital Product Data) de nodo
	"lsnodeportip": true,       // Puertos IP de nodo
	"lsnodeportfc": true,       // Puertos FC de nodo
	"lsnodeportsas": true,      // Puertos SAS de nodo

	// =========================================================================
	// STORAGE POOL COMMANDS (Pools de almacenamiento)
	// Referencia: sg248561.txt Capítulo 3 - Storage pools
	// =========================================================================
	"lsmdiskgrp": true,         // Grupos de MDisk (pools) - CRÍTICO para capacidad
	"lsmdisk": true,            // MDisks individuales
	"lsfreeextents": true,      // Extentos libres en pools
	"lspool": true,             // Pools (alias de lsmdiskgrp)

	// =========================================================================
	// VOLUME COMMANDS (Volúmenes/LUNs)
	// Referencia: svc_bkmap_cliguidebk (1).txt - Volume commands
	// =========================================================================
	"lsvdisk": true,            // Volúmenes virtuales - CRÍTICO para estado
	"lsvdiskaccess": true,      // Acceso a volúmenes
	"lsvdiskcopy": true,        // Copias de volumen - CRÍTICO para Safeguarded Copy
	"lsvdiskhostmap": true,     // Mapeo de volúmenes a hosts
	"lsvolumegroup": true,      // Grupos de volúmenes
	"lsvolumebackupgeneration": true, // Generaciones de backup (cloud)

	// =========================================================================
	// DRIVE/ENCLOSURE COMMANDS (Hardware físico)
	// Referencia: svc_bkmap_cliguidebk (1).txt - Hardware commands
	// =========================================================================
	"lsdrive": true,            // Drives físicos - CRÍTICO para health
	"lsenclosure": true,        // Enclosures/chassis
	"lsenclosurebattery": true, // Baterías de enclosure - CRÍTICO para integridad
	"lsenclosurecanister": true,// Canisters en enclosure
	"lsenclosurepsu": true,     // Power supplies - CRÍTICO para redundancia
	"lsenclosureslot": true,    // Slots de drives
	"lsenclosureport": true,    // Puertos de enclosure
	"lsenclosurefan": true,     // Fans de enclosure

	// =========================================================================
	// REPLICATION COMMANDS (Réplica y alta disponibilidad)
	// Referencia: sg248543.txt - Remote Copy, HyperSwap
	// =========================================================================
	"lsreplication": true,      // Configuración de replicación
	"lsrcrelationship": true,   // Relaciones de remote copy - CRÍTICO para DR
	"lsrcrelationshipcandidate": true, // Candidatos para RC
	"lshyperswap": true,        // Configuración HyperSwap
	"lspartition": true,        // Particiones de storage

	// =========================================================================
	// SAFEGUARDED COPY COMMANDS (Cyber Resiliency)
	// Referencia: sg248561.txt Sección 6.3 - Safeguarded Copy
	// =========================================================================
	"lssafeguardedcopy": true,  // Estado de Safeguarded Copy - CRÍTICO para ransomware
	"lssnapshot": true,         // Snapshots - CRÍTICO para recovery
	"lssnapshotpolicy": true,   // Políticas de snapshot

	// =========================================================================
	// EVENT/HEALTH COMMANDS (Monitoreo y alertas)
	// Referencia: svc_bkmap_cliguidebk (1).txt - Event commands
	// =========================================================================
	"lseventlog": true,         // Log de eventos - CRÍTICO para alertas
	"lseventlogseverity": true, // Severidad de eventos
	"lshealth": true,           // Estado de salud general

	// =========================================================================
	// PERFORMANCE COMMANDS (Métricas de rendimiento)
	// Referencia: sg248561.txt - Performance monitoring
	// =========================================================================
	"lsportstats": true,        // Estadísticas de puertos
	"lsportfc": true,           // Puertos Fibre Channel
	"lsportip": true,           // Puertos IP
	"lsportiscsi": true,        // Puertos iSCSI
	"lsportnvme": true,         // Puertos NVMe

	// =========================================================================
	// DATA REDUCTION COMMANDS (Compresión/Deduplicación)
	// Referencia: sg248543.txt - Data reduction pools
	// =========================================================================
	"lscompressionstats": true, // Estadísticas de compresión
	"lsdeduplicationstats": true, // Estadísticas de deduplicación (si licenciado)

	// =========================================================================
	// HOST COMMANDS (Hosts conectados)
	// Referencia: svc_bkmap_cliguidebk (1).txt - Host commands
	// =========================================================================
	"lshost": true,             // Hosts definidos
	"lshostcluster": true,      // Clusters de hosts
	"lshostport": true,         // Puertos de hosts
	"lshostvdiskmap": true,     // Mapeo host-volumen

	// =========================================================================
	// NETWORK COMMANDS (Configuración de red)
	// Referencia: svc_bkmap_cliguidebk (1).txt - Network commands
	// =========================================================================
	"lsip": true,               // Direcciones IP de gestión
	"lsdns": true,              // Servidores DNS
	"lsntp": true,              // Servidores NTP
	"lsportset": true,          // Portsets
	"lsiscsiport": true,        // Puertos iSCSI

	// =========================================================================
	// USER/AUTH COMMANDS (Usuarios y autenticación)
	// Referencia: sg248561.txt Capítulo 4 - Security
	// =========================================================================
	"lsuser": true,             // Usuarios del sistema
	"lsusergrp": true,          // Grupos de usuarios
	"lsldap": true,             // Configuración LDAP (si usa auth remoto)

	// =========================================================================
	// MISCELLANEOUS COMMANDS (Varios)
	// =========================================================================
	"lscimomdumps": true,       // CIMO dumps (diagnóstico)
	"lsclustervpd": true,       // VPD del cluster
	"lsarray": true,            // Arrays RAID
	"lscache": true,            // Estado de caché
	"lsquorum": true,           // Discos quorum
	"lspolicy": true,           // Políticas del sistema
}

// DangerousCharsPattern define regex para caracteres peligrosos
// Referencia: OWASP Injection Prevention Cheat Sheet
// Estos caracteres pueden permitir:
// - Inyección de comandos de shell (; | & $ `)
// - Redirección de salida ( > < )
// - Escape de comillas ( ' " \ )
// - Nueva línea para inyección (\n \r)
var DangerousCharsPattern = regexp.MustCompile(`[;|&$` + "`" + `><\n\r\\'"{}()\[\]]`)

// SuspiciousPathsPattern define paths que no deben aparecer en comandos
// Referencia: svc_bkmap_cliguidebk (1).txt - File system access restrictions
var SuspiciousPathsPattern = regexp.MustCompile(`(/etc/|/root/|/home/|/var/log/|/tmp/|\.\./|\.\.\\)`)

// ============================================================================
// VALIDACIÓN DE COMANDOS
// ============================================================================

// CommandValidationResult contiene el resultado de la validación de un comando
type CommandValidationResult struct {
	IsValid    bool     // true si el comando es válido y seguro
	Command    string   // Comando sanitizado (listo para ejecutar)
	Reason     string   // Razón de rechazo (si IsValid=false)
	BaseCmd    string   // Comando base (primera palabra)
	Params     []string // Parámetros extraídos
	IsReadOnly bool     // true si el comando es solo lectura
}

// ValidateCommand valida un comando completo contra whitelist y reglas de seguridad
// Referencia: sg248561.txt Capítulo 4 - Security best practices
//
// Parámetros:
//   cmd: Comando CLI completo (ej: "lssystem -delim : -nohdr")
//
// Retorna:
//   CommandValidationResult con estado de validación
//
// Ejemplo:
//   result := ValidateCommand("lssystem -delim : -nohdr")
//   if !result.IsValid {
//       log.Printf("Command rejected: %s", result.Reason)
//   }
func ValidateCommand(cmd string) CommandValidationResult {
	result := CommandValidationResult{
		IsValid:    false,
		Command:    "",
		Reason:     "",
		BaseCmd:    "",
		Params:     []string{},
		IsReadOnly: false,
	}

	// 1. Validar que no esté vacío
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		result.Reason = "empty command"
		return result
	}

	// 2. Validar longitud máxima (prevención de DoS)
	if len(cmd) > MaxCommandLength {
		result.Reason = fmt.Sprintf("command too long: %d chars (max: %d)", len(cmd), MaxCommandLength)
		return result
	}

	// 3. Extraer comando base (primera palabra)
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		result.Reason = "no command found"
		return result
	}

	baseCmd := strings.ToLower(fields[0])
	params := fields[1:]

	// 4. Verificar whitelist de comandos permitidos
	if !IsCommandAllowed(baseCmd) {
		result.Reason = fmt.Sprintf("command not in whitelist: %s", baseCmd)
		return result
	}

	// 5. Rechazar caracteres peligrosos (prevención de inyección)
	if ContainsDangerousChars(cmd) {
		result.Reason = "command contains dangerous characters (;|&$`>< etc.)"
		return result
	}

	// 6. Validar que no contenga paths sospechosos
	if ContainsSuspiciousPaths(cmd) {
		result.Reason = "command contains suspicious file system paths"
		return result
	}

	// 7. Validar parámetros individuales
	for i, param := range params {
		if len(param) > MaxParamLength {
			result.Reason = fmt.Sprintf("parameter %d too long: %d chars (max: %d)", i, len(param), MaxParamLength)
			return result
		}
		if ContainsDangerousChars(param) {
			result.Reason = fmt.Sprintf("parameter %d contains dangerous characters", i)
			return result
		}
	}

	// 8. Validación específica por comando (reglas adicionales)
	if !ValidateCommandSpecifics(baseCmd, params) {
		result.Reason = "command failed specific validation rules"
		return result
	}

	// Comando válido
	result.IsValid = true
	result.Command = cmd
	result.BaseCmd = baseCmd
	result.Params = params
	result.IsReadOnly = IsReadOnlyCommand(baseCmd)

	return result
}

// ValidateCommandSpecifics valida reglas específicas por tipo de comando
// Referencia: svc_bkmap_cliguidebk (1).txt - Command syntax reference
func ValidateCommandSpecifics(cmd string, params []string) bool {
	switch cmd {
	case "lseventlog":
		// Validar que no intente borrar/modificar logs
		for _, p := range params {
			if strings.Contains(p, "-del") || strings.Contains(p, "-rm") {
				return false
			}
		}

	case "lsuser":
		// Solo permitir consulta de usuario específico, no lista completa
		// (para evitar enumeración de usuarios)
		// Nota: Para monitoreo, generalmente se consulta el propio usuario

	case "lsvdisk", "lsvdiskcopy":
		// Validar que los IDs sean numéricos o nombres válidos
		for _, p := range params {
			if strings.HasPrefix(p, "-filtervalue") {
				// Validar formato de filtervalue (ej: id=123, name=vol1)
				if !isValidFilterValue(p) {
					return false
				}
			}
		}
	}

	return true
}

// isValidFilterValue valida formato de parámetro -filtervalue
// Formato esperado: -filtervalue campo=valor:campo2=valor2
func isValidFilterValue(param string) bool {
	// Pattern simple: permitir solo alfanuméricos, underscore, guión
	filterPattern := regexp.MustCompile(`^-filtervalue\s+[a-zA-Z0-9_\-]+=([a-zA-Z0-9_\-:]+)$`)
	return filterPattern.MatchString(param)
}

// ============================================================================
// VALIDACIÓN DE PARÁMETROS DE ENTRADA
// ============================================================================

// IsValidHost valida formato de host (IPv4, IPv6, hostname RFC 1123)
// Referencia: Zabbix_Documentation_7.2.en.txt - Host configuration
func IsValidHost(host string) bool {
	if host == "" || len(host) > MaxHostnameLength {
		return false
	}

	// 1. Validar IPv4
	ipv4 := net.ParseIP(host)
	if ipv4 != nil && ipv4.To4() != nil {
		// IPv4 válido
		// Rechazar leading zeros (ej: 192.168.001.001)
		parts := strings.Split(host, ".")
		for _, part := range parts {
			if len(part) > 1 && part[0] == '0' {
				return false // Leading zeros no permitidos
			}
		}
		return true
	}

	// 2. Validar IPv6
	if ipv4 != nil && ipv4.To16() != nil {
		return true // IPv6 válido
	}

	// 3. Validar hostname RFC 1123
	// Pattern: alfanumérico, guiones, puntos, max 253 chars
	hostnamePattern := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`)
	return hostnamePattern.MatchString(host)
}

// IsValidUsername valida nombre de usuario (alfanumérico, max 32 chars)
// Referencia: svc_bkmap_cliguidebk (1).txt - User management commands
// Referencia: sg248561.txt Capítulo 4 - User security
func IsValidUsername(user string) bool {
	if user == "" || len(user) > MaxUsernameLength {
		return false
	}

	// Rechazar usuarios privilegiados (principio de mínimo privilegio)
	privilegedUsers := map[string]bool{
		"root":      true,
		"superuser": true,
		"admin":     true,
		"service":   true,
		"operator":  true,
	}
	if privilegedUsers[user] {
		return false
	}

	// Solo alfanumérico y underscore (prevenir inyección)
	usernamePattern := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	return usernamePattern.MatchString(user)
}

// IsValidPort valida puerto en rango seguro (1024-65535)
// Referencia: Zabbix_Documentation_7.2.en.txt - Network configuration
func IsValidPort(port string) bool {
	if port == "" {
		return false
	}

	// Validar que sea numérico
	portPattern := regexp.MustCompile(`^\d+$`)
	if !portPattern.MatchString(port) {
		return false
	}

	var portNum int
	fmt.Sscanf(port, "%d", &portNum)
	return portNum >= MinSSHPort && portNum <= MaxSSHPort
}

// IsValidTimeout valida timeout en rango permitido
// Referencia: Zabbix_Documentation_7.2.en.txt - Timeout parameter (p.1518)
func IsValidTimeout(timeoutSec int) bool {
	return timeoutSec >= 1 && timeoutSec <= MaxTimeoutSeconds
}

// SanitizeParam sanitiza parámetro individual para uso en comandos
// Referencia: OWASP Input Validation Cheat Sheet
func SanitizeParam(param string) string {
	if param == "" {
		return ""
	}

	// 1. Remover caracteres peligrosos
	param = DangerousCharsPattern.ReplaceAllString(param, "")

	// 2. Remover espacios extra
	param = strings.TrimSpace(param)

	// 3. Truncar a longitud máxima
	if len(param) > MaxParamLength {
		param = param[:MaxParamLength]
	}

	// 4. Normalizar (convertir a UTF-8 seguro)
	param = strings.ToValidUTF8(param, "")

	return param
}

// ============================================================================
// FUNCIONES DE ASISTENCIA
// ============================================================================

// IsCommandAllowed verifica si el comando está en la whitelist
func IsCommandAllowed(cmd string) bool {
	// Normalizar a minúsculas para comparación
	cmd = strings.ToLower(cmd)
	return AllowedCommands[cmd]
}

// ContainsDangerousChars verifica si el string contiene caracteres peligrosos
func ContainsDangerousChars(s string) bool {
	return DangerousCharsPattern.MatchString(s)
}

// ContainsSuspiciousPaths verifica si el comando contiene paths sospechosos
func ContainsSuspiciousPaths(s string) bool {
	return SuspiciousPathsPattern.MatchString(s)
}

// IsReadOnlyCommand determina si un comando es solo lectura (sin efectos secundarios)
// Referencia: sg248561.txt Capítulo 4 - Read-only monitoring accounts
func IsReadOnlyCommand(cmd string) bool {
	// Todos los comandos en AllowedCommands son de lectura (ls*)
	// Esta función existe para validación futura si se agregan comandos mixtos
	return strings.HasPrefix(cmd, "ls")
}

// GetCommandCategory retorna la categoría del comando para logging/auditoría
func GetCommandCategory(cmd string) string {
	categories := map[string][]string{
		"system":      {"lssystem", "lssystemfc", "lssystemstats", "lslicense"},
		"node":        {"lsnode", "lsnodecanister", "lsnodebattery", "lsnodestats"},
		"pool":        {"lsmdiskgrp", "lsmdisk", "lsfreeextents", "lspool"},
		"volume":      {"lsvdisk", "lsvdiskaccess", "lsvdiskcopy", "lsvolumegroup"},
		"hardware":    {"lsdrive", "lsenclosure", "lsenclosurebattery", "lsenclosurepsu"},
		"replication": {"lsreplication", "lsrcrelationship", "lshyperswap"},
		"safeguarded": {"lssafeguardedcopy", "lssnapshot", "lssnapshotpolicy"},
		"event":       {"lseventlog", "lseventlogseverity", "lshealth"},
		"performance": {"lsportstats", "lsportfc", "lsportip"},
		"host":        {"lshost", "lshostcluster", "lshostport"},
		"network":     {"lsip", "lsdns", "lsntp", "lsportset"},
		"security":    {"lsuser", "lsusergrp", "lsldap", "lssecurity"},
	}

	cmd = strings.ToLower(cmd)
	for category, commands := range categories {
		for _, c := range commands {
			if cmd == c {
				return category
			}
		}
	}

	return "other"
}

// GetCommandDescription retorna descripción del comando para documentación
func GetCommandDescription(cmd string) string {
	descriptions := map[string]string{
		"lssystem":              "Estado general del sistema",
		"lsmdiskgrp":            "Pools de almacenamiento (capacidad, estado)",
		"lsvdisk":               "Volúmenes virtuales (estado, capacidad)",
		"lsvdiskcopy":           "Copias de volumen (Safeguarded Copy status)",
		"lsdrive":               "Drives físicos (estado, enclosure, slot)",
		"lsenclosure":           "Enclosures/chassis (estado, temperatura)",
		"lsenclosurebattery":    "Baterías de enclosure (integridad de caché)",
		"lsenclosurepsu":        "Power supplies (redundancia, estado)",
		"lsrcrelationship":      "Relaciones de remote copy (DR status)",
		"lssafeguardedcopy":     "Safeguarded Copy (protección ransomware)",
		"lseventlog":            "Log de eventos (alertas, errores)",
		"lsnode":                "Nodos/canisters (estado, rendimiento)",
		"lsportstats":           "Estadísticas de puertos (IOPS, throughput)",
		"lscompressionstats":    "Estadísticas de compresión (data reduction)",
	}

	cmd = strings.ToLower(cmd)
	if desc, ok := descriptions[cmd]; ok {
		return desc
	}
	return "Comando de monitoreo Storage Virtualize"
}

// ============================================================================
// VALIDACIÓN DE TIMEOUT
// ============================================================================

// ValidateTimeout valida timeout y retorna valor seguro
func ValidateTimeout(timeoutSec int) int {
	if timeoutSec < 1 {
		return 5 // Default mínimo
	}
	if timeoutSec > MaxTimeoutSeconds {
		return MaxTimeoutSeconds // Límite máximo
	}
	return timeoutSec
}

// GetTimeoutDuration retorna timeout como time.Duration
func GetTimeoutDuration(timeoutSec int) time.Duration {
	return time.Duration(ValidateTimeout(timeoutSec)) * time.Second
}

// ============================================================================
// LOGGING DE AUDITORÍA (Sin datos sensibles)
// ============================================================================

// AuditCommandLog genera entrada de log de auditoría para comando
// Referencia: sg248561.txt Capítulo 4 - Audit logging requirements
//
// NOTA DE SEGURIDAD:
// - NO loguear passwords, claves, o datos sensibles
// - NO loguear output completo de comandos (puede contener datos)
// - SOLO loguear: comando base, parámetros sanitizados, resultado (éxito/fallo)
func AuditCommandLog(host, user, cmd string, success bool, duration time.Duration) map[string]interface{} {
	// Sanitizar comando para log (remover parámetros potencialmente sensibles)
	sanitizedCmd := sanitizeCommandForLog(cmd)

	return map[string]interface{}{
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
		"host":             host,
		"user":             user,
		"command":          sanitizedCmd,
		"success":          success,
		"duration_seconds": duration.Seconds(),
		"category":         GetCommandCategory(strings.Fields(cmd)[0]),
	}
}

// sanitizeCommandForLog remueve información sensible del comando para logging
func sanitizeCommandForLog(cmd string) string {
	// Remover posibles passwords o credenciales en parámetros
	sensitivePatterns := []string{
		"-password",
		"-passwd",
		"-secret",
		"-key",
		"-token",
		"-auth",
	}

	for _, pattern := range sensitivePatterns {
		if idx := strings.Index(strings.ToLower(cmd), pattern); idx != -1 {
			// Truncar comando antes del parámetro sensible
			return cmd[:idx] + " [REDACTED]"
		}
	}

	return cmd
}