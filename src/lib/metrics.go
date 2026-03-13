// lib/metrics.go
// Funciones de métricas para IBM FlashSystem 5045/7300/9500 y SAN Volume Controller
// Compatible con Storage Virtualize V8.7
//
// Referencias de documentación:
// - svc_bkmap_cliguidebk (1).txt: CLI Command Reference (todos los comandos ls*)
// - sg248561.txt: IBM Storage Virtualize V8.7 Redbook
//   - Capítulo 3: Storage pools y capacidad
//   - Sección 6.3: Safeguarded Copy (Cyber Resiliency)
//   - Capítulo 4: Security y audit logging
// - sg248543.txt: Data Reduction & Replication
//   - Capítulo 7: HyperSwap y Remote Copy
//   - Capítulo 10: CLI usage para replicación
// - Zabbix_Documentation_7.2.en.txt: ExternalCheck specification (p.1518)
//   - Formato de salida para items: valor simple o JSON para LLD
//
// Principios de diseño:
// 1. Salida limpia: solo el valor métrico (sin logs en stdout)
// 2. Valores Zabbix-compatible: "1"/"0" para estado, números para métricas
// 3. JSON válido para Low-Level Discovery
// 4. Logging seguro: auditoría en archivo, nunca en stdout
// 5. Timeout estricto: < Timeout en zabbix_server.conf (30s)
//
// Compilación:
//   cd src && go build -o ibm_flash_monitor .
//
// Uso:
//   status, err := lib.SystemHealthStatus(client)
//   capacity, err := lib.PoolCapacityUsedPercent(client, "0")

package lib

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// CONSTANTES Y ESTRUCTURAS
// ============================================================================

const (
	// Estados estándar para métricas de estado (Zabbix compatible)
	StatusOnline      = "1"  // Online/Healthy
	StatusOffline     = "0"  // Offline/Failed
	StatusWarning     = "2"  // Warning/Degraded
	StatusUnknown     = "3"  // Unknown/Not Found
	StatusNotConfig   = "-1" // Not Configured
)

// PoolMetric contiene métricas de pool para LLD
type PoolMetric struct {
	PoolID       string `json:"{#POOL_ID}"`
	PoolName     string `json:"{#POOL_NAME}"`
	PoolStatus   string `json:"{#POOL_STATUS}"`
	Capacity     string `json:"{#POOL_CAPACITY_BYTES}"`
	UsedCapacity string `json:"{#POOL_USED_BYTES}"`
	FreeCapacity string `json:"{#POOL_FREE_BYTES}"`
}

// VolumeMetric contiene métricas de volumen para LLD
type VolumeMetric struct {
	VolumeID   string `json:"{#VDISK_ID}"`
	VolumeName string `json:"{#VDISK_NAME}"`
	VolumeStatus string `json:"{#VDISK_STATUS}"`
	PoolID     string `json:"{#POOL_ID}"`
	Capacity   string `json:"{#VDISK_CAPACITY_BYTES}"`
}

// DriveMetric contiene métricas de drive para LLD
type DriveMetric struct {
	DriveID     string `json:"{#DRIVE_ID}"`
	DriveName   string `json:"{#DRIVE_NAME}"`
	EnclosureID string `json:"{#ENCLOSURE_ID}"`
	SlotID      string `json:"{#SLOT_ID}"`
	DriveStatus string `json:"{#DRIVE_STATUS}"`
	DriveType   string `json:"{#DRIVE_TYPE}"`
}

// SafeguardedVolumeMetric contiene métricas de Safeguarded Copy para LLD
type SafeguardedVolumeMetric struct {
	VolumeID      string `json:"{#VDISK_ID}"`
	VolumeName    string `json:"{#VDISK_NAME}"`
	SafeguardedStatus string `json:"{#SAFEGUARDED_STATUS}"`
	ExpiryTime    string `json:"{#SAFEGUARDED_EXPIRY_HOURS}"`
	PolicyName    string `json:"{#SNAPSHOT_POLICY_NAME}"`
}

// ReplicationMetric contiene métricas de replicación para LLD
type ReplicationMetric struct {
	RelationshipID   string `json:"{#RC_RELATIONSHIP_ID}"`
	RelationshipName string `json:"{#RC_RELATIONSHIP_NAME}"`
	MasterVolumeID   string `json:"{#RC_MASTER_VOLUME_ID}"`
	AuxVolumeID      string `json:"{#RC_AUX_VOLUME_ID}"`
	ReplicationStatus string `json:"{#RC_STATUS}"`
	ReplicationType  string `json:"{#RC_TYPE}"`
}

// ============================================================================
// SAFEGUARDED COPY MONITORING
// Referencia: sg248561.txt Sección 6.3 - Safeguarded Copy (Cyber Resiliency)
// ============================================================================

// SafeguardedCopyStatus retorna estado de Safeguarded Copy para un volumen
// Comando: lsvdiskcopy -filtervalue id=<vdisk_id> -delim : -nohdr
// Referencia: svc_bkmap_cliguidebk (1).txt - lsvdiskcopy command
//
// Retorna:
//   "1"  = Safeguarded Copy configurada y saludable
//   "0"  = Safeguarded Copy con problemas
//   "-1" = No configurado
//   "3"  = Desconocido/Error
func SafeguardedCopyStatus(client *SecureSSHClient, vdiskID string) (string, error) {
	cmd := fmt.Sprintf("lsvdiskcopy -filtervalue id=%s -delim : -nohdr", SanitizeParam(vdiskID))
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		LogError("SafeguardedCopyStatus command failed", err)
		return StatusUnknown, err
	}

	if output == "" {
		return StatusNotConfig, nil
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) < 20 {
			continue
		}

		// Campo 18: safeguarded_copy (yes/no) - según svc_bkmap_cliguidebk
		safeguarded := strings.ToLower(strings.TrimSpace(fields[18]))
		if safeguarded != "yes" {
			continue
		}

		// Campo 2: status (online, offline, synchronized, etc.)
		status := strings.ToLower(strings.TrimSpace(fields[2]))

		switch status {
		case "online", "synchronized", "consistent_synchronized":
			return StatusOnline, nil
		case "offline", "stopped", "error", "inconsistent":
			return StatusOffline, nil
		case "synchronizing", "copying", "preparing":
			return StatusWarning, nil
		default:
			return StatusUnknown, nil
		}
	}

	return StatusNotConfig, nil
}

// SafeguardedCopyExpiryHours retorna horas restantes hasta expiración de Safeguarded Copy
// Para alertas proactivas antes de que expire la copia inmutable
// Comando: lsvdiskcopy -filtervalue id=<vdisk_id> -delim : -nohdr
// Referencia: sg248561.txt Sección 6.3 - Safeguarded Copy retention
func SafeguardedCopyExpiryHours(client *SecureSSHClient, vdiskID string) (string, error) {
	cmd := fmt.Sprintf("lsvdiskcopy -filtervalue id=%s -delim : -nohdr", SanitizeParam(vdiskID))
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		LogError("SafeguardedCopyExpiryHours command failed", err)
		return "0", err
	}

	if output == "" {
		return "0", nil
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) < 25 {
			continue
		}

		// Campo 18: safeguarded_copy (yes/no)
		safeguarded := strings.ToLower(strings.TrimSpace(fields[18]))
		if safeguarded != "yes" {
			continue
		}

		// Campo 23: expiry_time (formato: YYYY-MM-DD HH:MM:SS o "-" si no configurado)
		expiry := strings.TrimSpace(fields[23])
		if expiry == "" || expiry == "-" {
			return "0", nil
		}

		// Parsear timestamp de expiración
		expiryTime, err := time.Parse("2006-01-02 15:04:05", expiry)
		if err != nil {
			// Intentar formato alternativo
			expiryTime, err = time.Parse("2006-01-02T15:04:05", expiry)
			if err != nil {
				LogWarning("Failed to parse expiry time", map[string]interface{}{
					"vdisk_id": vdiskID,
					"expiry":   expiry,
					"error":    err.Error(),
				})
				return "0", nil
			}
		}

		// Calcular horas restantes
		hoursRemaining := expiryTime.Sub(time.Now()).Hours()
		if hoursRemaining < 0 {
			return "0", nil // Ya expiró
		}

		return fmt.Sprintf("%.0f", hoursRemaining), nil
	}

	return "0", nil
}

// SafeguardedCopyPolicyName retorna nombre de la política de snapshot asociada
// Comando: lsvdiskcopy -filtervalue id=<vdisk_id> -delim : -nohdr
func SafeguardedCopyPolicyName(client *SecureSSHClient, vdiskID string) (string, error) {
	cmd := fmt.Sprintf("lsvdiskcopy -filtervalue id=%s -delim : -nohdr", SanitizeParam(vdiskID))
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return "", err
	}

	if output == "" {
		return "not_configured", nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 30 {
		return "unknown", nil
	}

	// Campo 28: snapshot_policy_name (puede variar según versión)
	policy := strings.TrimSpace(fields[28])
	if policy == "" || policy == "-" {
		return "not_configured", nil
	}

	return policy, nil
}

// ============================================================================
// CAPACITY & SPACE MONITORING
// Referencia: sg248561.txt Capítulo 3 - Storage pools
// Referencia: sg248543.txt - Data reduction pools
// ============================================================================

// PoolCapacityUsedPercent retorna porcentaje de capacidad usada del pool
// Comando: lsmdiskgrp <pool_id> -delim : -nohdr
// Referencia: svc_bkmap_cliguidebk (1).txt - lsmdiskgrp command
//
// Campos de salida (según documentación):
//   [0]=id, [1]=name, [2]=status, [5]=capacity, [6]=used_capacity, [7]=free_capacity
func PoolCapacityUsedPercent(client *SecureSSHClient, poolID string) (string, error) {
	cmd := fmt.Sprintf("lsmdiskgrp %s -delim : -nohdr", SanitizeParam(poolID))
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		LogError("PoolCapacityUsedPercent command failed", err)
		return "0", err
	}

	if output == "" {
		return "0", nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 8 {
		return "0", fmt.Errorf("invalid output format: expected at least 8 fields")
	}

	// Parsear capacidad total y usada (puede incluir unidades: TB, GB, MB)
	capacity, err := ParseSizeToBytes(fields[5]) // total capacity
	if err != nil {
		LogWarning("Failed to parse total capacity", map[string]interface{}{
			"pool_id": poolID,
			"value":   fields[5],
			"error":   err.Error(),
		})
		return "0", nil
	}

	used, err := ParseSizeToBytes(fields[6]) // used capacity
	if err != nil {
		LogWarning("Failed to parse used capacity", map[string]interface{}{
			"pool_id": poolID,
			"value":   fields[6],
			"error":   err.Error(),
		})
		return "0", nil
	}

	if capacity == 0 {
		return "0", nil
	}

	percent := float64(used) / float64(capacity) * 100
	return fmt.Sprintf("%.2f", percent), nil
}

// PoolFreeCapacityBytes retorna capacidad libre en bytes
// Para triggers de espacio crítico (ej: < 100GB libres)
func PoolFreeCapacityBytes(client *SecureSSHClient, poolID string) (string, error) {
	cmd := fmt.Sprintf("lsmdiskgrp %s -delim : -nohdr", SanitizeParam(poolID))
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return "0", err
	}

	if output == "" {
		return "0", nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 8 {
		return "0", nil
	}

	freeBytes, err := ParseSizeToBytes(fields[7]) // free_capacity field
	if err != nil {
		return "0", err
	}

	return strconv.FormatInt(freeBytes, 10), nil
}

// PoolTotalCapacityBytes retorna capacidad total del pool en bytes
func PoolTotalCapacityBytes(client *SecureSSHClient, poolID string) (string, error) {
	cmd := fmt.Sprintf("lsmdiskgrp %s -delim : -nohdr", SanitizeParam(poolID))
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return "0", err
	}

	if output == "" {
		return "0", nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 6 {
		return "0", nil
	}

	totalBytes, err := ParseSizeToBytes(fields[5]) // capacity field
	if err != nil {
		return "0", err
	}

	return strconv.FormatInt(totalBytes, 10), nil
}

// PoolCompressionRatio retorna ratio de compresión para pools con data reduction
// Referencia: sg248543.txt - Data reduction estimation tools
// Comando: lsmdiskgrp <pool_id> -delim : -nohdr
func PoolCompressionRatio(client *SecureSSHClient, poolID string) (string, error) {
	cmd := fmt.Sprintf("lsmdiskgrp %s -delim : -nohdr", SanitizeParam(poolID))
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return "1.00", err
	}

	if output == "" {
		return "1.00", nil
	}

	fields := strings.Split(output, ":")
	// Campo 14: compression_ratio (según svc_bkmap_cliguidebk)
	if len(fields) < 15 {
		return "1.00", nil
	}

	ratio := strings.TrimSpace(fields[14])
	if ratio == "" || ratio == "-" {
		return "1.00", nil
	}

	// Validar que sea número válido
	if _, err := strconv.ParseFloat(ratio, 64); err != nil {
		return "1.00", nil
	}

	return ratio, nil
}

// PoolStatus retorna estado del pool (online/offline)
// Comando: lsmdiskgrp <pool_id> -delim : -nohdr
func PoolStatus(client *SecureSSHClient, poolID string) (string, error) {
	cmd := fmt.Sprintf("lsmdiskgrp %s -delim : -nohdr", SanitizeParam(poolID))
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return StatusUnknown, err
	}

	if output == "" {
		return StatusUnknown, nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 3 {
		return StatusUnknown, nil
	}

	status := strings.ToLower(strings.TrimSpace(fields[2]))

	switch status {
	case "online", "stable":
		return StatusOnline, nil
	case "offline", "degraded", "error":
		return StatusOffline, nil
	case "starting", "stopping":
		return StatusWarning, nil
	default:
		return StatusUnknown, nil
	}
}

// ============================================================================
// VOLUME MONITORING
// Referencia: svc_bkmap_cliguidebk (1).txt - Volume commands
// ============================================================================

// VolumeStatus retorna estado de un volumen específico
// Comando: lsvdisk <vdisk_id> -delim : -nohdr
func VolumeStatus(client *SecureSSHClient, vdiskID string) (string, error) {
	cmd := fmt.Sprintf("lsvdisk %s -delim : -nohdr", SanitizeParam(vdiskID))
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return StatusUnknown, err
	}

	if output == "" {
		return StatusUnknown, nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 5 {
		return StatusUnknown, nil
	}

	// Campo 4: status (según svc_bkmap_cliguidebk)
	status := strings.ToLower(strings.TrimSpace(fields[4]))

	switch status {
	case "online", "mapped", "synchronized":
		return StatusOnline, nil
	case "offline", "stopped", "error", "failed":
		return StatusOffline, nil
	case "starting", "stopping", "migrating":
		return StatusWarning, nil
	default:
		return StatusUnknown, nil
	}
}

// VolumeCapacityBytes retorna capacidad de volumen en bytes
// Comando: lsvdisk <vdisk_id> -delim : -nohdr
func VolumeCapacityBytes(client *SecureSSHClient, vdiskID string) (string, error) {
	cmd := fmt.Sprintf("lsvdisk %s -delim : -nohdr", SanitizeParam(vdiskID))
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return "0", err
	}

	if output == "" {
		return "0", nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 4 {
		return "0", nil
	}

	// Campo 3: capacity (según svc_bkmap_cliguidebk)
	capacity, err := ParseSizeToBytes(fields[3])
	if err != nil {
		return "0", err
	}

	return strconv.FormatInt(capacity, 10), nil
}

// VolumeMapped retorna si el volumen está mapeado a hosts (1=yes, 0=no)
// Comando: lsvdisk <vdisk_id> -delim : -nohdr
func VolumeMapped(client *SecureSSHClient, vdiskID string) (string, error) {
	cmd := fmt.Sprintf("lsvdisk %s -delim : -nohdr", SanitizeParam(vdiskID))
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return "0", err
	}

	if output == "" {
		return "0", nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 10 {
		return "0", nil
	}

	// Campo 9: mapped (yes/no) - según documentación
	mapped := strings.ToLower(strings.TrimSpace(fields[9]))
	if mapped == "yes" {
		return "1", nil
	}
	return "0", nil
}

// ============================================================================
// REPLICATION & HIGH AVAILABILITY
// Referencia: sg248543.txt Capítulo 7 - HyperSwap, Remote Copy
// ============================================================================

// ReplicationStatus retorna estado de relación de replicación remota
// Comando: lsrcrelationship <rel_id> -delim : -nohdr
// Referencia: sg248543.txt - Remote Copy monitoring
func ReplicationStatus(client *SecureSSHClient, relID string) (string, error) {
	cmd := fmt.Sprintf("lsrcrelationship %s -delim : -nohdr", SanitizeParam(relID))
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return StatusUnknown, err
	}

	if output == "" {
		return StatusUnknown, nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 10 {
		return StatusUnknown, nil
	}

	// Campo 2: status (según svc_bkmap_cliguidebk)
	status := strings.ToLower(strings.TrimSpace(fields[2]))

	switch status {
	case "consistent_synchronized", "idling", "preparing", "consistent":
		return StatusOnline, nil
	case "inconsistent", "stopped", "error", "disconnected", "failed":
		return StatusOffline, nil
	case "synchronizing", "copying", "initializing":
		return StatusWarning, nil
	default:
		return StatusUnknown, nil
	}
}

// ReplicationLagSeconds retorna lag de replicación en segundos
// Para alertas de replicación desfasada
// Comando: lsrcrelationship <rel_id> -delim : -nohdr
func ReplicationLagSeconds(client *SecureSSHClient, relID string) (string, error) {
	cmd := fmt.Sprintf("lsrcrelationship %s -delim : -nohdr", SanitizeParam(relID))
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return "0", err
	}

	if output == "" {
		return "0", nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 15 {
		return "0", nil
	}

	// Campo 12: replication_lag (formato: número o "-")
	lag := strings.TrimSpace(fields[12])
	if lag == "" || lag == "-" {
		return "0", nil
	}

	// Validar que sea número
	if _, err := strconv.ParseInt(lag, 10, 64); err != nil {
		return "0", nil
	}

	return lag, nil
}

// HyperSwapVolumeStatus verifica si un volumen está configurado como HyperSwap
// y retorna estado de ambas copias (local/remote)
// Comando: lsvdisk <vdisk_id> -delim : -nohdr
// Referencia: sg248543.txt - HyperSwap configuration
func HyperSwapVolumeStatus(client *SecureSSHClient, vdiskID string) (string, error) {
	cmd := fmt.Sprintf("lsvdisk %s -delim : -nohdr", SanitizeParam(vdiskID))
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return StatusUnknown, err
	}

	if output == "" {
		return StatusUnknown, nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 30 {
		return StatusUnknown, nil
	}

	// Campo 25: hyper_swap (yes/no) - según documentación V8.7
	isHyperSwap := strings.ToLower(strings.TrimSpace(fields[25]))
	if isHyperSwap != "yes" {
		return StatusNotConfig, nil
	}

	// Verificar estado de ambas copias
	// Campo 4: status (primary copy)
	status1 := strings.ToLower(strings.TrimSpace(fields[4]))
	// Campo 15: auxiliary status (aproximado, puede variar)
	status2 := strings.ToLower(strings.TrimSpace(fields[15]))

	if status1 == "online" && status2 == "online" {
		return StatusOnline, nil // Both copies healthy
	} else if status1 == "online" || status2 == "online" {
		return StatusWarning, nil // One copy degraded
	}

	return StatusOffline, nil // Both copies down
}

// ============================================================================
// HARDWARE HEALTH MONITORING
// Referencia: svc_bkmap_cliguidebk (1).txt - Hardware commands
// ============================================================================

// DriveStatus retorna estado de drive específico (enclosure_id:drive_id)
// Comando: lsdrive -filtervalue enclosure_id=<enc>:id=<drive> -delim : -nohdr
func DriveStatus(client *SecureSSHClient, enclosureID, driveID string) (string, error) {
	cmd := fmt.Sprintf("lsdrive -filtervalue enclosure_id=%s:id=%s -delim : -nohdr",
		SanitizeParam(enclosureID), SanitizeParam(driveID))
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return StatusUnknown, err
	}

	if output == "" {
		return StatusUnknown, nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 5 {
		return StatusUnknown, nil
	}

	// Campo 1: status (online, offline, failed, etc.)
	status := strings.ToLower(strings.TrimSpace(fields[1]))

	switch status {
	case "online", "online:degraded", "active":
		return StatusOnline, nil
	case "offline", "failed", "error", "missing":
		return StatusOffline, nil
	case "rebuilding", "synchronizing", "initializing":
		return StatusWarning, nil
	default:
		return StatusUnknown, nil
	}
}

// EnclosureBatteryStatus retorna estado de batería de enclosure
// CRÍTICO para data integrity (protección de caché)
// Comando: lsenclosurebattery -filtervalue enclosure_id=<enc>:battery_id=<bat> -delim : -nohdr
// Referencia: sg248543.txt - Battery backup for write cache
func EnclosureBatteryStatus(client *SecureSSHClient, enclosureID, batteryID string) (string, error) {
	cmd := fmt.Sprintf("lsenclosurebattery -filtervalue enclosure_id=%s:battery_id=%s -delim : -nohdr",
		SanitizeParam(enclosureID), SanitizeParam(batteryID))
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return StatusUnknown, err
	}

	if output == "" {
		return StatusUnknown, nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 5 {
		return StatusUnknown, nil
	}

	// Campo 2: status (online, offline, charging, failed)
	status := strings.ToLower(strings.TrimSpace(fields[2]))

	switch status {
	case "online", "charging", "charged":
		return StatusOnline, nil
	case "offline", "failed", "missing", "discharged":
		return StatusOffline, nil // CRÍTICO - data at risk
	case "discharging", "reconditioning":
		return StatusWarning, nil
	default:
		return StatusUnknown, nil
	}
}

// EnclosureStatus retorna estado de enclosure
// Comando: lsenclosure <enclosure_id> -delim : -nohdr
func EnclosureStatus(client *SecureSSHClient, enclosureID string) (string, error) {
	cmd := fmt.Sprintf("lsenclosure %s -delim : -nohdr", SanitizeParam(enclosureID))
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return StatusUnknown, err
	}

	if output == "" {
		return StatusUnknown, nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 3 {
		return StatusUnknown, nil
	}

	// Campo 1: status
	status := strings.ToLower(strings.TrimSpace(fields[1]))

	switch status {
	case "online", "stable":
		return StatusOnline, nil
	case "offline", "degraded", "error":
		return StatusOffline, nil
	default:
		return StatusUnknown, nil
	}
}

// EnclosurePSUStatus retorna estado de power supply unit
// Comando: lsenclosurepsu -filtervalue enclosure_id=<enc>:PSU_id=<psu> -delim : -nohdr
func EnclosurePSUStatus(client *SecureSSHClient, enclosureID, psuID string) (string, error) {
	cmd := fmt.Sprintf("lsenclosurepsu -filtervalue enclosure_id=%s:PSU_id=%s -delim : -nohdr",
		SanitizeParam(enclosureID), SanitizeParam(psuID))
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return StatusUnknown, err
	}

	if output == "" {
		return StatusUnknown, nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 5 {
		return StatusUnknown, nil
	}

	// Campo 2: status
	status := strings.ToLower(strings.TrimSpace(fields[2]))

	switch status {
	case "online", "active", "present":
		return StatusOnline, nil
	case "offline", "failed", "missing", "error":
		return StatusOffline, nil
	default:
		return StatusUnknown, nil
	}
}

// NodeCanisterStatus retorna estado de node/canister
// Comando: lsenclosurecanister -filtervalue enclosure_id=<enc>:node_id=<node> -delim : -nohdr
func NodeCanisterStatus(client *SecureSSHClient, enclosureID, nodeID string) (string, error) {
	cmd := fmt.Sprintf("lsenclosurecanister -filtervalue enclosure_id=%s:node_id=%s -delim : -nohdr",
		SanitizeParam(enclosureID), SanitizeParam(nodeID))
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return StatusUnknown, err
	}

	if output == "" {
		return StatusUnknown, nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 5 {
		return StatusUnknown, nil
	}

	// Campo 2: status
	status := strings.ToLower(strings.TrimSpace(fields[2]))

	switch status {
	case "online", "active", "candidate":
		return StatusOnline, nil
	case "offline", "failed", "error", "missing":
		return StatusOffline, nil
	default:
		return StatusUnknown, nil
	}
}

// ArrayStatus retorna estado de array MDisk
// Comando: lsarray <array_id> -delim : -nohdr
func ArrayStatus(client *SecureSSHClient, arrayID string) (string, error) {
	cmd := fmt.Sprintf("lsarray %s -delim : -nohdr", SanitizeParam(arrayID))
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return StatusUnknown, err
	}

	if output == "" {
		return StatusUnknown, nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 5 {
		return StatusUnknown, nil
	}

	// Campo 2: status
	status := strings.ToLower(strings.TrimSpace(fields[2]))

	switch status {
	case "online", "synchronized", "active":
		return StatusOnline, nil
	case "offline", "degraded", "failed", "error":
		return StatusOffline, nil
	case "synchronizing", "rebuilding":
		return StatusWarning, nil
	default:
		return StatusUnknown, nil
	}
}

// ============================================================================
// SYSTEM HEALTH & EVENT MONITORING
// Referencia: svc_bkmap_cliguidebk (1).txt - Event commands
// Referencia: sg248561.txt Capítulo 4 - Audit logging
// ============================================================================

// SystemHealthStatus retorna estado general del sistema
// Comando: lssystem -delim : -nohdr
// Referencia: svc_bkmap_cliguidebk (1).txt - lssystem command
func SystemHealthStatus(client *SecureSSHClient) (string, error) {
	cmd := "lssystem -delim : -nohdr"
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return StatusUnknown, err
	}

	if output == "" {
		return StatusUnknown, nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 5 {
		return StatusUnknown, nil
	}

	// Campo 1: status (según documentación)
	status := strings.ToLower(strings.TrimSpace(fields[1]))

	switch status {
	case "online", "stable", "active":
		return StatusOnline, nil
	case "degraded", "offline", "error", "failed":
		return StatusOffline, nil
	case "starting", "stopping", "initializing":
		return StatusWarning, nil
	default:
		return StatusUnknown, nil
	}
}

// CriticalEventsCount retorna número de eventos críticos no resueltos
// Comando: lseventlog -filtervalue severity=critical -fixed no -nohdr | wc -l
// Referencia: sg248561.txt - Event monitoring
func CriticalEventsCount(client *SecureSSHClient) (string, error) {
	cmd := "lseventlog -filtervalue severity=critical -fixed no -nohdr"
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return "0", err
	}

	if output == "" {
		return "0", nil
	}

	// Contar líneas (cada línea es un evento)
	lines := strings.Split(strings.TrimSpace(output), "\n")
	count := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}

	return strconv.Itoa(count), nil
}

// WarningEventsCount retorna número de eventos warning no resueltos
func WarningEventsCount(client *SecureSSHClient) (string, error) {
	cmd := "lseventlog -filtervalue severity=warning -fixed no -nohdr"
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return "0", err
	}

	if output == "" {
		return "0", nil
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	count := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}

	return strconv.Itoa(count), nil
}

// SystemName retorna nombre del sistema (para inventario)
// Comando: lssystem -delim : -nohdr
func SystemName(client *SecureSSHClient) (string, error) {
	cmd := "lssystem -delim : -nohdr"
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return "", err
	}

	if output == "" {
		return "", nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 2 {
		return "", nil
	}

	// Campo 0: name (según documentación)
	return strings.TrimSpace(fields[0]), nil
}

// SystemSerial retorna número de serial del sistema (para inventario)
// Comando: lssystem -delim : -nohdr
func SystemSerial(client *SecureSSHClient) (string, error) {
	cmd := "lssystem -delim : -nohdr"
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return "", err
	}

	if output == "" {
		return "", nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 10 {
		return "", nil
	}

	// Campo 9: serial_number (puede variar según versión)
	return strings.TrimSpace(fields[9]), nil
}

// SystemVersion retorna versión de software (para inventario)
// Comando: lssystem -delim : -nohdr
func SystemVersion(client *SecureSSHClient) (string, error) {
	cmd := "lssystem -delim : -nohdr"
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return "", err
	}

	if output == "" {
		return "", nil
	}

	fields := strings.Split(output, ":")
	if len(fields) < 6 {
		return "", nil
	}

	// Campo 5: software_version
	return strings.TrimSpace(fields[5]), nil
}

// ============================================================================
// LOW-LEVEL DISCOVERY FUNCTIONS
// Referencia: Zabbix_Documentation_7.2.en.txt - Low-level discovery (p.1520)
// Formato JSON: {"data": [{"{#MACRO}": "value"}, ...]}
// ============================================================================

// DiscoverPools retorna JSON LLD para pools de almacenamiento
// Comando: lsmdiskgrp -nohdr -delim :
func DiscoverPools(client *SecureSSHClient) (string, error) {
	cmd := "lsmdiskgrp -nohdr -delim :"
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return `{"data":[]}`, err
	}

	var data []PoolMetric
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 8 {
			capacity, _ := ParseSizeToBytes(fields[5])
			used, _ := ParseSizeToBytes(fields[6])
			free, _ := ParseSizeToBytes(fields[7])

			data = append(data, PoolMetric{
				PoolID:       strings.TrimSpace(fields[0]),
				PoolName:     strings.TrimSpace(fields[1]),
				PoolStatus:   strings.TrimSpace(fields[2]),
				Capacity:     strconv.FormatInt(capacity, 10),
				UsedCapacity: strconv.FormatInt(used, 10),
				FreeCapacity: strconv.FormatInt(free, 10),
			})
		}
	}

	// Ordenar por PoolID para consistencia
	sort.Slice(data, func(i, j int) bool {
		return data[i].PoolID < data[j].PoolID
	})

	result := map[string]interface{}{"data": data}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return `{"data":[]}`, err
	}

	return string(jsonBytes), nil
}

// DiscoverSafeguardedVolumes retorna JSON LLD para volúmenes con Safeguarded Copy
// Comando: lsvdiskcopy -filtervalue safeguarded_copy=yes -nohdr -delim :
func DiscoverSafeguardedVolumes(client *SecureSSHClient) (string, error) {
	cmd := "lsvdiskcopy -filtervalue safeguarded_copy=yes -nohdr -delim :"
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return `{"data":[]}`, err
	}

	var data []SafeguardedVolumeMetric
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 25 {
			// Calcular horas restantes
			expiryHours := "0"
			expiry := strings.TrimSpace(fields[23])
			if expiry != "" && expiry != "-" {
				expiryTime, err := time.Parse("2006-01-02 15:04:05", expiry)
				if err == nil {
					hours := expiryTime.Sub(time.Now()).Hours()
					if hours > 0 {
						expiryHours = fmt.Sprintf("%.0f", hours)
					}
				}
			}

			data = append(data, SafeguardedVolumeMetric{
				VolumeID:        strings.TrimSpace(fields[0]),
				VolumeName:      strings.TrimSpace(fields[1]),
				SafeguardedStatus: strings.TrimSpace(fields[2]),
				ExpiryTime:      expiryHours,
				PolicyName:      strings.TrimSpace(fields[28]),
			})
		}
	}

	sort.Slice(data, func(i, j int) bool {
		return data[i].VolumeID < data[j].VolumeID
	})

	result := map[string]interface{}{"data": data}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return `{"data":[]}`, err
	}

	return string(jsonBytes), nil
}

// DiscoverDrives retorna JSON LLD para drives físicos
// Comando: lsdrive -nohdr -delim :
func DiscoverDrives(client *SecureSSHClient) (string, error) {
	cmd := "lsdrive -nohdr -delim :"
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return `{"data":[]}`, err
	}

	var data []DriveMetric
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 11 {
			data = append(data, DriveMetric{
				DriveID:     strings.TrimSpace(fields[0]),
				DriveName:   strings.TrimSpace(fields[1]),
				EnclosureID: strings.TrimSpace(fields[9]),
				SlotID:      strings.TrimSpace(fields[10]),
				DriveStatus: strings.TrimSpace(fields[2]),
				DriveType:   strings.TrimSpace(fields[3]),
			})
		}
	}

	sort.Slice(data, func(i, j int) bool {
		return data[i].EnclosureID < data[j].EnclosureID ||
			(data[i].EnclosureID == data[j].EnclosureID && data[i].SlotID < data[j].SlotID)
	})

	result := map[string]interface{}{"data": data}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return `{"data":[]}`, err
	}

	return string(jsonBytes), nil
}

// DiscoverVolumes retorna JSON LLD para volúmenes
// Comando: lsvdisk -nohdr -delim :
func DiscoverVolumes(client *SecureSSHClient) (string, error) {
	cmd := "lsvdisk -nohdr -delim :"
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return `{"data":[]}`, err
	}

	var data []VolumeMetric
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 8 {
			capacity, _ := ParseSizeToBytes(fields[3])

			data = append(data, VolumeMetric{
				VolumeID:     strings.TrimSpace(fields[0]),
				VolumeName:   strings.TrimSpace(fields[1]),
				VolumeStatus: strings.TrimSpace(fields[4]),
				PoolID:       strings.TrimSpace(fields[7]),
				Capacity:     strconv.FormatInt(capacity, 10),
			})
		}
	}

	sort.Slice(data, func(i, j int) bool {
		return data[i].VolumeID < data[j].VolumeID
	})

	result := map[string]interface{}{"data": data}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return `{"data":[]}`, err
	}

	return string(jsonBytes), nil
}

// DiscoverReplications retorna JSON LLD para relaciones de replicación
// Comando: lsrcrelationship -nohdr -delim :
func DiscoverReplications(client *SecureSSHClient) (string, error) {
	cmd := "lsrcrelationship -nohdr -delim :"
	output, err := client.ExecuteCommand(cmd)
	if err != nil {
		return `{"data":[]}`, err
	}

	var data []ReplicationMetric
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 15 {
			data = append(data, ReplicationMetric{
				RelationshipID:   strings.TrimSpace(fields[0]),
				RelationshipName: strings.TrimSpace(fields[1]),
				MasterVolumeID:   strings.TrimSpace(fields[3]),
				AuxVolumeID:      strings.TrimSpace(fields[4]),
				ReplicationStatus: strings.TrimSpace(fields[2]),
				ReplicationType:  strings.TrimSpace(fields[5]),
			})
		}
	}

	sort.Slice(data, func(i, j int) bool {
		return data[i].RelationshipID < data[j].RelationshipID
	})

	result := map[string]interface{}{"data": data}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return `{"data":[]}`, err
	}

	return string(jsonBytes), nil
}

// ============================================================================
// FUNCIONES DE ASISTENCIA
// ============================================================================

// ParseSizeToBytes convierte string de tamaño (ej: "10.5TB", "500GB") a bytes
// Referencia: sg248561.txt - Capacity units
func ParseSizeToBytes(sizeStr string) (int64, error) {
	sizeStr = strings.TrimSpace(sizeStr)
	if sizeStr == "" || sizeStr == "-" {
		return 0, nil
	}

	// Regex para parsear número + unidad
	re := regexp.MustCompile(`^([\d.]+)\s*([KMGTPEZY]?[Bb]?)?$`)
	matches := re.FindStringSubmatch(strings.ToUpper(sizeStr))
	if len(matches) < 2 {
		return 0, fmt.Errorf("invalid size format: %s", sizeStr)
	}

	value, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, err
	}

	unit := ""
	if len(matches) >= 3 {
		unit = matches[2]
	}

	multiplier := int64(1)

	switch unit {
	case "K", "KB", "KIB":
		multiplier = 1024
	case "M", "MB", "MIB":
		multiplier = 1024 * 1024
	case "G", "GB", "GIB":
		multiplier = 1024 * 1024 * 1024
	case "T", "TB", "TIB":
		multiplier = 1024 * 1024 * 1024 * 1024
	case "P", "PB", "PIB":
		multiplier = 1024 * 1024 * 1024 * 1024 * 1024
	case "E", "EB", "EIB":
		multiplier = 1024 * 1024 * 1024 * 1024 * 1024 * 1024
	}

	return int64(value * float64(multiplier)), nil
}

// FormatBytesToHuman convierte bytes a formato legible (ej: 1073741824 -> "1.00GB")
func FormatBytesToHuman(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// IsValidStatus verifica si un valor de estado es válido para Zabbix
func IsValidStatus(status string) bool {
	validStatuses := map[string]bool{
		StatusOnline:    true,
		StatusOffline:   true,
		StatusWarning:   true,
		StatusUnknown:   true,
		StatusNotConfig: true,
	}
	return validStatuses[status]
}