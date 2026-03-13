// src/main.go
// IBM FlashSystem Monitor para Zabbix 7.2 ExternalCheck
// Compatible con IBM Storage Virtualize V8.7 (FS5045, FS7300, FS9500, SVC)
// 
// Requisitos de Seguridad:
// - Ejecutar como usuario 'zabbix' (no root)
// - SSH Key-based auth con ED25519 (sin password)
// - Logging a archivo, NUNCA a stdout
// - Validación estricta de parámetros (prevención de inyección)
// - Timeout explícito < Timeout en zabbix_server.conf (30s)
//
// Referencias:
// - sg248561.txt: IBM Storage Virtualize V8.7 Redbook
// - svc_bkmap_cliguidebk (1).txt: CLI Command Reference
// - Zabbix_Documentation_7.2.en.txt: ExternalCheck specification
//
// Compilación:
//   cd src && go build -o ibm_flash_monitor .
//
// Instalación:
//   sudo cp ibm_flash_monitor /usr/lib/zabbix/externalscripts/
//   sudo chown zabbix:zabbix /usr/lib/zabbix/externalscripts/ibm_flash_monitor
//   sudo chmod 750 /usr/lib/zabbix/externalscripts/ibm_flash_monitor

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"zabbix-ibm-flash/lib"
)

// ============================================================================
// CONSTANTES DE CONFIGURACIÓN
// ============================================================================

const (
	// Ruta de configuración (NO modificar sin actualizar documentación)
	CONFIG_DIR     = "/opt/zabbix-ibm-flash/config"
	KEY_PATH       = CONFIG_DIR + "/id_ibm_flash"
	KNOWN_HOSTS    = CONFIG_DIR + "/known_hosts"
	SECRETS_FILE   = CONFIG_DIR + "/secrets.env"
	
	// Timeout por defecto (debe ser < Timeout en zabbix_server.conf)
	DEFAULT_TIMEOUT = 25 // segundos
	
	// Usuario SSH por defecto (solo lectura)
	DEFAULT_USER = "zabbix_monitor"
	
	// Puerto SSH estándar
	SSH_PORT = "22"
)

// ============================================================================
// ESTRUCTURA DE COMANDO
// ============================================================================

// CommandStruct representa un comando a ejecutar
type CommandStruct struct {
	action       string   // Acción a realizar (ej: discover_pools, get_pool_capacity)
	params       []string // Parámetros adicionales
	isDiscovery  bool     // true si es comando de descubrimiento LLD
}

// ============================================================================
// FUNCIÓN PRINCIPAL
// ============================================================================

func main() {
	// Validar parámetros mínimos: <host> <action> [params...]
	if len(os.Args) < 3 {
		fmt.Println("SCRIPT_ERROR")
		os.Exit(1)
	}
	
	// Sanitizar entrada (prevención de inyección)
	host := lib.SanitizeParam(os.Args[1])
	action := lib.SanitizeParam(os.Args[2])
	params := make([]string, len(os.Args)-3)
	for i, p := range os.Args[3:] {
		params[i] = lib.SanitizeParam(p)
	}
	
	// Validar host (prevención SSRF)
	if !lib.IsValidHost(host) {
		fmt.Println("SCRIPT_ERROR")
		os.Exit(1)
	}
	
	// Construir estructura de comando
	cmd := CommandStruct{
		action:      action,
		params:      params,
		isDiscovery: strings.HasPrefix(action, "discover_"),
	}
	
	// Ejecutar comando y capturar resultado
	result, err := executeCommand(host, cmd)
	
	// Manejar errores
	if err != nil {
		// NO imprimir error a stdout - Zabbix lo interpretaría como dato
		// El error ya está logueado en executeCommand
		fmt.Println("SCRIPT_ERROR")
		os.Exit(1)
	}
	
	// Output para Zabbix: solo el valor, sin espacios extra
	// Para LLD: JSON válido
	// Para métricas: valor simple (ej: "85.20", "1", "0")
	fmt.Println(strings.TrimSpace(result))
	os.Exit(0)
}

// ============================================================================
// EJECUCIÓN DE COMANDOS
// ============================================================================

// executeCommand inicializa SSH y ejecuta la acción solicitada
func executeCommand(host string, cmd CommandStruct) (string, error) {
	// Inicializar cliente SSH seguro
	client, err := lib.NewSecureSSHClient(
		host,
		DEFAULT_USER,
		SSH_PORT,
		KEY_PATH,
		KNOWN_HOSTS,
		DEFAULT_TIMEOUT,
	)
	if err != nil {
		lib.LogError("SSH client initialization failed", err)
		return "", err
	}
	
	// Ejecutar acción solicitada
	var result string
	switch cmd.action {
	// ========================================================================
	// LOW-LEVEL DISCOVERY (Generación dinámica de items)
	// ========================================================================
	case "discover_pools":
		result, err = lib.DiscoverPools(client)
		
	case "discover_safeguarded_volumes":
		result, err = lib.DiscoverSafeguardedVolumes(client)
		
	case "discover_drives":
		result, err = lib.DiscoverDrives(client)
		
	case "discover_enclosures":
		result, err = lib.DiscoverEnclosures(client)
		
	case "discover_arrays":
		result, err = lib.DiscoverArrays(client)
		
	case "discover_volumes":
		result, err = lib.DiscoverVolumes(client)
	
	// ========================================================================
	// SAFEGUARDED COPY MONITORING (Cyber Resiliency)
	// Referencia: sg248561.txt sección 6.3
	// ========================================================================
	case "safeguarded_copy_status":
		if len(cmd.params) < 1 {
			return "", fmt.Errorf("missing vdisk_id parameter")
		}
		result, err = lib.SafeguardedCopyStatus(client, cmd.params[0])
		
	case "safeguarded_copy_expiry_hours":
		if len(cmd.params) < 1 {
			return "", fmt.Errorf("missing vdisk_id parameter")
		}
		result, err = lib.SafeguardedCopyExpiry(client, cmd.params[0])
	
	// ========================================================================
	// CAPACITY & SPACE MONITORING
	// Referencia: sg248561.txt (Capacity monitoring), svc_bkmap_cliguidebk (1).txt
	// ========================================================================
	case "pool_capacity_used_percent":
		if len(cmd.params) < 1 {
			return "", fmt.Errorf("missing pool_id parameter")
		}
		result, err = lib.PoolCapacityUsedPercent(client, cmd.params[0])
		
	case "pool_free_capacity_bytes":
		if len(cmd.params) < 1 {
			return "", fmt.Errorf("missing pool_id parameter")
		}
		result, err = lib.PoolFreeCapacityBytes(client, cmd.params[0])
		
	case "pool_compression_ratio":
		if len(cmd.params) < 1 {
			return "", fmt.Errorf("missing pool_id parameter")
		}
		result, err = lib.VolumeCompressionRatio(client, cmd.params[0])
		
	case "pool_total_capacity_bytes":
		if len(cmd.params) < 1 {
			return "", fmt.Errorf("missing pool_id parameter")
		}
		result, err = lib.PoolTotalCapacityBytes(client, cmd.params[0])
	
	// ========================================================================
	// REPLICATION & HIGH AVAILABILITY
	// Referencia: sg248543.txt - HyperSwap, Remote Copy, Stretched Cluster
	// ========================================================================
	case "replication_status":
		if len(cmd.params) < 1 {
			return "", fmt.Errorf("missing relationship_id parameter")
		}
		result, err = lib.ReplicationStatus(client, cmd.params[0])
		
	case "hyperswap_volume_status":
		if len(cmd.params) < 1 {
			return "", fmt.Errorf("missing vdisk_id parameter")
		}
		result, err = lib.HyperSwapVolumeStatus(client, cmd.params[0])
		
	case "replication_lag_seconds":
		if len(cmd.params) < 1 {
			return "", fmt.Errorf("missing relationship_id parameter")
		}
		result, err = lib.ReplicationLagSeconds(client, cmd.params[0])
	
	// ========================================================================
	// HARDWARE HEALTH MONITORING
	// Referencia: svc_bkmap_cliguidebk (1).txt - Hardware components
	// ========================================================================
	case "drive_status":
		if len(cmd.params) < 2 {
			return "", fmt.Errorf("missing enclosure_id or drive_id parameter")
		}
		result, err = lib.DriveStatus(client, cmd.params[0], cmd.params[1])
		
	case "enclosure_battery_status":
		if len(cmd.params) < 2 {
			return "", fmt.Errorf("missing enclosure_id or battery_id parameter")
		}
		result, err = lib.EnclosureBatteryStatus(client, cmd.params[0], cmd.params[1])
		
	case "enclosure_status":
		if len(cmd.params) < 1 {
			return "", fmt.Errorf("missing enclosure_id parameter")
		}
		result, err = lib.EnclosureStatus(client, cmd.params[0])
		
	case "enclosure_psu_status":
		if len(cmd.params) < 2 {
			return "", fmt.Errorf("missing enclosure_id or psu_id parameter")
		}
		result, err = lib.EnclosurePSUStatus(client, cmd.params[0], cmd.params[1])
		
	case "node_canister_status":
		if len(cmd.params) < 2 {
			return "", fmt.Errorf("missing enclosure_id or node_id parameter")
		}
		result, err = lib.NodeCanisterStatus(client, cmd.params[0], cmd.params[1])
		
	case "array_status":
		if len(cmd.params) < 1 {
			return "", fmt.Errorf("missing array_id parameter")
		}
		result, err = lib.ArrayStatus(client, cmd.params[0])
	
	// ========================================================================
	// SYSTEM HEALTH & EVENT MONITORING
	// ========================================================================
	case "system_health":
		result, err = lib.SystemHealthStatus(client)
		
	case "critical_events_count":
		result, err = lib.CriticalEventsCount(client)
		
	case "warning_events_count":
		result, err = lib.WarningEventsCount(client)
		
	case "system_name":
		result, err = lib.SystemName(client)
		
	case "system_serial":
		result, err = lib.SystemSerial(client)
	
	// ========================================================================
	// VOLUME MONITORING
	// ========================================================================
	case "volume_status":
		if len(cmd.params) < 1 {
			return "", fmt.Errorf("missing vdisk_id parameter")
		}
		result, err = lib.VolumeStatus(client, cmd.params[0])
		
	case "volume_capacity_bytes":
		if len(cmd.params) < 1 {
			return "", fmt.Errorf("missing vdisk_id parameter")
		}
		result, err = lib.VolumeCapacityBytes(client, cmd.params[0])
		
	case "volume_compressed_bytes":
		if len(cmd.params) < 1 {
			return "", fmt.Errorf("missing vdisk_id parameter")
		}
		result, err = lib.VolumeCompressedBytes(client, cmd.params[0])
	
	// ========================================================================
	// FALLBACK - Acción no reconocida
	// ========================================================================
	default:
		lib.LogError("Unknown action", fmt.Errorf("action: %s", cmd.action))
		return "", fmt.Errorf("unknown action: %s", cmd.action)
	}
	
	return result, err
}

// ============================================================================
// FUNCIONES DE ASISTENCIA
// ============================================================================

// validateParams valida que los parámetros no contengan caracteres peligrosos
func validateParams(params []string) bool {
	for _, p := range params {
		if lib.ContainsDangerousChars(p) {
			return false
		}
	}
	return true
}

// ============================================================================
// PRUEBAS MANUALES (descomentar para debugging)
// ============================================================================

// Para pruebas manuales, ejecutar:
//   sudo -u zabbix /usr/lib/zabbix/externalscripts/ibm_flash_monitor <ip> system_health
//
// Expected outputs:
//   system_health              -> "1" (online) o "0" (offline)
//   discover_pools             -> {"data":[{"{#POOL_ID}":"0",...},...]}
//   pool_capacity_used_percent -> "78.45" (porcentaje)
//   safeguarded_copy_status    -> "1" (healthy), "0" (problem), "not_configured"
//   drive_status               -> "1" (online), "0" (failed)
//   SCRIPT_ERROR               -> Error de ejecución (ver logs)
//
// Logs location:
//   /opt/zabbix-ibm-flash/logs/ibm_flash_monitor.log
//
// Troubleshooting:
//   1. Verificar permisos de clave SSH: stat -c '%a %U:%G' /opt/zabbix-ibm-flash/config/id_ibm_flash
//   2. Verificar contexto SELinux: ls -Z /usr/lib/zabbix/externalscripts/ibm_flash_monitor
//   3. Verificar logs: sudo tail -f /opt/zabbix-ibm-flash/logs/ibm_flash_monitor.log
//   4. Probar conexión SSH: sudo -u zabbix ssh -i /opt/zabbix-ibm-flash/config/id_ibm_flash zabbix_monitor@<ip> "lssystem"