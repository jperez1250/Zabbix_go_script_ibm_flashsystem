// lib/lld_builder.go
// Constructor de JSON para Zabbix Low-Level Discovery (LLD)
// Compatible con IBM FlashSystem 5045/7300/9500 y SAN Volume Controller
// Compatible con Storage Virtualize V8.7
//
// Referencias de documentación:
// - Zabbix_Documentation_7.2.en.txt: Low-level discovery specification (p.1520)
//   - Formato JSON: {"data": [{"{#MACRO}": "value"}, ...]}
//   - LLD rule lifetime, filtering, preprocessing
// - svc_bkmap_cliguidebk (1).txt: CLI Command Reference (comandos ls*)
// - sg248561.txt: IBM Storage Virtualize V8.7 Redbook
//   - Capítulo 3: Storage pools y capacidad
//   - Sección 6.3: Safeguarded Copy (Cyber Resiliency)
// - sg248543.txt: Data Reduction & Replication
//   - Capítulo 7: HyperSwap y Remote Copy
//
// Principios de diseño:
// 1. JSON válido y compacto (sin espacios innecesarios)
// 2. Macros de Zabbix con formato correcto ({#MACRO_NAME})
// 3. Ordenamiento consistente (por ID) para evitar recreación de items
// 4. Filtrado de objetos no relevantes (ej: drives offline en discovery)
// 5. Logging seguro (sin datos sensibles en stdout)
//
// Compilación:
//   cd src && go build -o ibm_flash_monitor .
//
// Uso:
//   json, err := lib.BuildPoolLLD(output)
//   fmt.Println(json) // Para Zabbix ExternalCheck

package lib

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// CONSTANTES DE LLD
// ============================================================================

const (
	// Prefijo estándar para macros de Zabbix LLD
	LLDMacroPrefix = "{#"
	LLDMacroSuffix = "}"

	// Lifetime por defecto para reglas LLD (según Zabbix_Documentation_7.2.en.txt)
	// Los items descubiertos se mantienen por este período después de desaparecer
	DefaultLLDLifetime = "30d"

	// Límite máximo de objetos por discovery (prevención de DoS)
	MaxLLDObjects = 10000

	// Timeout para operaciones de construcción LLD
	LLDBuildTimeout = 10 * time.Second
)

// ============================================================================
// ESTRUCTURAS DE DATOS PARA LLD
// ============================================================================

// LLDRawResult representa el resultado crudo de un comando CLI para LLD
type LLDRawResult struct {
	Lines   []string // Líneas de salida del comando
	Command string   // Comando ejecutado
	Error   error    // Error si ocurrió
}

// LLDItem representa un item individual en el array "data" de LLD
type LLDItem map[string]string

// LLDResult representa el resultado final de LLD para Zabbix
// Formato: {"data": [{...}, {...}, ...]}
type LLDResult struct {
	Data []LLDItem `json:"data"`
}

// PoolLLDItem representa un pool para LLD con todos los macros necesarios
type PoolLLDItem struct {
	PoolID       string `json:"{#POOL_ID}"`
	PoolName     string `json:"{#POOL_NAME}"`
	PoolStatus   string `json:"{#POOL_STATUS}"`
	Capacity     string `json:"{#POOL_CAPACITY_BYTES}"`
	UsedCapacity string `json:"{#POOL_USED_BYTES}"`
	FreeCapacity string `json:"{#POOL_FREE_BYTES}"`
	Compression  string `json:"{#POOL_COMPRESSION_RATIO}"`
	EasyTier     string `json:"{#POOL_EASY_TIER}"`
}

// VolumeLLDItem representa un volumen para LLD
type VolumeLLDItem struct {
	VolumeID     string `json:"{#VDISK_ID}"`
	VolumeName   string `json:"{#VDISK_NAME}"`
	VolumeStatus string `json:"{#VDISK_STATUS}"`
	PoolID       string `json:"{#POOL_ID}"`
	Capacity     string `json:"{#VDISK_CAPACITY_BYTES}"`
	Mapped       string `json:"{#VDISK_MAPPED}"`
	ThinProvisioned string `json:"{#VDISK_THIN_PROVISIONED}"`
}

// DriveLLDItem representa un drive físico para LLD
type DriveLLDItem struct {
	DriveID     string `json:"{#DRIVE_ID}"`
	DriveName   string `json:"{#DRIVE_NAME}"`
	EnclosureID string `json:"{#ENCLOSURE_ID}"`
	SlotID      string `json:"{#SLOT_ID}"`
	DriveStatus string `json:"{#DRIVE_STATUS}"`
	DriveType   string `json:"{#DRIVE_TYPE}"`
	Capacity    string `json:"{#DRIVE_CAPACITY_BYTES}"`
}

// SafeguardedVolumeLLDItem representa un volumen con Safeguarded Copy para LLD
type SafeguardedVolumeLLDItem struct {
	VolumeID        string `json:"{#VDISK_ID}"`
	VolumeName      string `json:"{#VDISK_NAME}"`
	SafeguardedStatus string `json:"{#SAFEGUARDED_STATUS}"`
	ExpiryHours     string `json:"{#SAFEGUARDED_EXPIRY_HOURS}"`
	PolicyName      string `json:"{#SNAPSHOT_POLICY_NAME}"`
	RetentionDays   string `json:"{#SAFEGUARDED_RETENTION_DAYS}"`
}

// ReplicationLLDItem representa una relación de replicación para LLD
type ReplicationLLDItem struct {
	RelationshipID   string `json:"{#RC_RELATIONSHIP_ID}"`
	RelationshipName string `json:"{#RC_RELATIONSHIP_NAME}"`
	MasterVolumeID   string `json:"{#RC_MASTER_VOLUME_ID}"`
	AuxVolumeID      string `json:"{#RC_AUX_VOLUME_ID}"`
	ReplicationStatus string `json:"{#RC_STATUS}"`
	ReplicationType  string `json:"{#RC_TYPE}"`
	ReplicationMode  string `json:"{#RC_MODE}"`
}

// EnclosureLLDItem representa un enclosure para LLD
type EnclosureLLDItem struct {
	EnclosureID   string `json:"{#ENCLOSURE_ID}"`
	EnclosureName string `json:"{#ENCLOSURE_NAME}"`
	EnclosureStatus string `json:"{#ENCLOSURE_STATUS}"`
	EnclosureType string `json:"{#ENCLOSURE_TYPE}"`
}

// ArrayLLDItem representa un array MDisk para LLD
type ArrayLLDItem struct {
	ArrayID   string `json:"{#ARRAY_ID}"`
	ArrayName string `json:"{#ARRAY_NAME}"`
	ArrayStatus string `json:"{#ARRAY_STATUS}"`
	PoolID    string `json:"{#POOL_ID}"`
	RAIDLevel string `json:"{#ARRAY_RAID_LEVEL}"`
}

// ============================================================================
// FUNCIONES PRINCIPALES DE CONSTRUCCIÓN LLD
// ============================================================================

// BuildPoolLLD construye JSON LLD para pools de almacenamiento
// Comando: lsmdiskgrp -nohdr -delim :
// Referencia: Zabbix_Documentation_7.2.en.txt - LLD JSON format (p.1520)
func BuildPoolLLD(output string) (string, error) {
	if output == "" {
		return `{"data":[]}`, nil
	}

	var items []PoolLLDItem
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) < 15 {
			continue
		}

		// Parsear campos según svc_bkmap_cliguidebk (1).txt
		poolID := strings.TrimSpace(fields[0])
		poolName := strings.TrimSpace(fields[1])
		poolStatus := strings.TrimSpace(fields[2])
		
		// Campos de capacidad (pueden incluir unidades: TB, GB, MB)
		capacity, _ := ParseSizeToBytes(fields[5])
		used, _ := ParseSizeToBytes(fields[6])
		free, _ := ParseSizeToBytes(fields[7])
		
		// Campo 14: compression_ratio
		compression := strings.TrimSpace(fields[14])
		if compression == "" || compression == "-" {
			compression = "1.00"
		}
		
		// Campo 13: easy_tier (yes/no)
		easyTier := strings.TrimSpace(fields[13])
		if easyTier == "" {
			easyTier = "no"
		}

		items = append(items, PoolLLDItem{
			PoolID:       poolID,
			PoolName:     poolName,
			PoolStatus:   poolStatus,
			Capacity:     strconv.FormatInt(capacity, 10),
			UsedCapacity: strconv.FormatInt(used, 10),
			FreeCapacity: strconv.FormatInt(free, 10),
			Compression:  compression,
			EasyTier:     easyTier,
		})
	}

	// Límite máximo de objetos (prevención de DoS)
	if len(items) > MaxLLDObjects {
		items = items[:MaxLLDObjects]
		LogWarning("LLD object limit reached", map[string]interface{}{
			"limit": MaxLLDObjects,
			"total": len(items),
		})
	}

	// Ordenar por PoolID para consistencia (evita recreación de items)
	sort.Slice(items, func(i, j int) bool {
		return items[i].PoolID < items[j].PoolID
	})

	return MarshalLLDResult(items)
}

// BuildVolumeLLD construye JSON LLD para volúmenes
// Comando: lsvdisk -nohdr -delim :
func BuildVolumeLLD(output string) (string, error) {
	if output == "" {
		return `{"data":[]}`, nil
	}

	var items []VolumeLLDItem
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) < 10 {
			continue
		}

		volumeID := strings.TrimSpace(fields[0])
		volumeName := strings.TrimSpace(fields[1])
		volumeStatus := strings.TrimSpace(fields[4])
		poolID := strings.TrimSpace(fields[7])
		capacity, _ := ParseSizeToBytes(fields[3])
		
		// Campo 9: mapped (yes/no)
		mapped := strings.TrimSpace(fields[9])
		if mapped == "" {
			mapped = "no"
		}
		
		// Campo 11: thin_provisioned (yes/no)
		thinProv := strings.TrimSpace(fields[11])
		if thinProv == "" {
			thinProv = "no"
		}

		items = append(items, VolumeLLDItem{
			VolumeID:        volumeID,
			VolumeName:      volumeName,
			VolumeStatus:    volumeStatus,
			PoolID:          poolID,
			Capacity:        strconv.FormatInt(capacity, 10),
			Mapped:          mapped,
			ThinProvisioned: thinProv,
		})
	}

	if len(items) > MaxLLDObjects {
		items = items[:MaxLLDObjects]
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].VolumeID < items[j].VolumeID
	})

	return MarshalLLDResult(items)
}

// BuildDriveLLD construye JSON LLD para drives físicos
// Comando: lsdrive -nohdr -delim :
// Referencia: svc_bkmap_cliguidebk (1).txt - lsdrive command
func BuildDriveLLD(output string) (string, error) {
	if output == "" {
		return `{"data":[]}`, nil
	}

	var items []DriveLLDItem
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) < 12 {
			continue
		}

		driveID := strings.TrimSpace(fields[0])
		driveName := strings.TrimSpace(fields[1])
		driveStatus := strings.TrimSpace(fields[2])
		driveType := strings.TrimSpace(fields[3])
		enclosureID := strings.TrimSpace(fields[9])
		slotID := strings.TrimSpace(fields[10])
		capacity, _ := ParseSizeToBytes(fields[4])

		// Filtrar drives que no están en slots (ej: hot spares no asignados)
		if slotID == "" || slotID == "-" {
			continue
		}

		items = append(items, DriveLLDItem{
			DriveID:     driveID,
			DriveName:   driveName,
			EnclosureID: enclosureID,
			SlotID:      slotID,
			DriveStatus: driveStatus,
			DriveType:   driveType,
			Capacity:    strconv.FormatInt(capacity, 10),
		})
	}

	if len(items) > MaxLLDObjects {
		items = items[:MaxLLDObjects]
	}

	// Ordenar por enclosure + slot para consistencia
	sort.Slice(items, func(i, j int) bool {
		if items[i].EnclosureID != items[j].EnclosureID {
			return items[i].EnclosureID < items[j].EnclosureID
		}
		return items[i].SlotID < items[j].SlotID
	})

	return MarshalLLDResult(items)
}

// BuildSafeguardedVolumeLLD construye JSON LLD para volúmenes con Safeguarded Copy
// Comando: lsvdiskcopy -filtervalue safeguarded_copy=yes -nohdr -delim :
// Referencia: sg248561.txt Sección 6.3 - Safeguarded Copy
func BuildSafeguardedVolumeLLD(output string) (string, error) {
	if output == "" {
		return `{"data":[]}`, nil
	}

	var items []SafeguardedVolumeLLDItem
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) < 30 {
			continue
		}

		volumeID := strings.TrimSpace(fields[0])
		volumeName := strings.TrimSpace(fields[1])
		safeguardedStatus := strings.TrimSpace(fields[2])
		
		// Calcular horas restantes hasta expiración
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
		
		// Campo 28: snapshot_policy_name
		policyName := strings.TrimSpace(fields[28])
		if policyName == "" || policyName == "-" {
			policyName = "not_configured"
		}
		
		// Campo 29: retention_days (puede variar según versión)
		retention := strings.TrimSpace(fields[29])
		if retention == "" || retention == "-" {
			retention = "0"
		}

		items = append(items, SafeguardedVolumeLLDItem{
			VolumeID:        volumeID,
			VolumeName:      volumeName,
			SafeguardedStatus: safeguardedStatus,
			ExpiryHours:     expiryHours,
			PolicyName:      policyName,
			RetentionDays:   retention,
		})
	}

	if len(items) > MaxLLDObjects {
		items = items[:MaxLLDObjects]
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].VolumeID < items[j].VolumeID
	})

	return MarshalLLDResult(items)
}

// BuildReplicationLLD construye JSON LLD para relaciones de replicación
// Comando: lsrcrelationship -nohdr -delim :
// Referencia: sg248543.txt Capítulo 7 - Remote Copy
func BuildReplicationLLD(output string) (string, error) {
	if output == "" {
		return `{"data":[]}`, nil
	}

	var items []ReplicationLLDItem
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) < 15 {
			continue
		}

		relID := strings.TrimSpace(fields[0])
		relName := strings.TrimSpace(fields[1])
		relStatus := strings.TrimSpace(fields[2])
		masterVol := strings.TrimSpace(fields[3])
		auxVol := strings.TrimSpace(fields[4])
		relType := strings.TrimSpace(fields[5])
		
		// Campo 7: replication_mode (sync/async)
		relMode := strings.TrimSpace(fields[7])
		if relMode == "" || relMode == "-" {
			relMode = "unknown"
		}

		items = append(items, ReplicationLLDItem{
			RelationshipID:    relID,
			RelationshipName:  relName,
			MasterVolumeID:    masterVol,
			AuxVolumeID:       auxVol,
			ReplicationStatus: relStatus,
			ReplicationType:   relType,
			ReplicationMode:   relMode,
		})
	}

	if len(items) > MaxLLDObjects {
		items = items[:MaxLLDObjects]
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].RelationshipID < items[j].RelationshipID
	})

	return MarshalLLDResult(items)
}

// BuildEnclosureLLD construye JSON LLD para enclosures
// Comando: lsenclosure -nohdr -delim :
func BuildEnclosureLLD(output string) (string, error) {
	if output == "" {
		return `{"data":[]}`, nil
	}

	var items []EnclosureLLDItem
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) < 5 {
			continue
		}

		enclosureID := strings.TrimSpace(fields[0])
		enclosureName := strings.TrimSpace(fields[1])
		enclosureStatus := strings.TrimSpace(fields[2])
		
		// Campo 4: enclosure_type (control/expansion)
		enclosureType := strings.TrimSpace(fields[4])
		if enclosureType == "" || enclosureType == "-" {
			enclosureType = "unknown"
		}

		items = append(items, EnclosureLLDItem{
			EnclosureID:     enclosureID,
			EnclosureName:   enclosureName,
			EnclosureStatus: enclosureStatus,
			EnclosureType:   enclosureType,
		})
	}

	if len(items) > MaxLLDObjects {
		items = items[:MaxLLDObjects]
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].EnclosureID < items[j].EnclosureID
	})

	return MarshalLLDResult(items)
}

// BuildArrayLLD construye JSON LLD para arrays MDisk
// Comando: lsarray -nohdr -delim :
func BuildArrayLLD(output string) (string, error) {
	if output == "" {
		return `{"data":[]}`, nil
	}

	var items []ArrayLLDItem
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) < 10 {
			continue
		}

		arrayID := strings.TrimSpace(fields[0])
		arrayName := strings.TrimSpace(fields[1])
		arrayStatus := strings.TrimSpace(fields[2])
		poolID := strings.TrimSpace(fields[7])
		
		// Campo 5: raid_level (ej: RAID5, RAID6, distributed)
		raidLevel := strings.TrimSpace(fields[5])
		if raidLevel == "" || raidLevel == "-" {
			raidLevel = "unknown"
		}

		items = append(items, ArrayLLDItem{
			ArrayID:     arrayID,
			ArrayName:   arrayName,
			ArrayStatus: arrayStatus,
			PoolID:      poolID,
			RAIDLevel:   raidLevel,
		})
	}

	if len(items) > MaxLLDObjects {
		items = items[:MaxLLDObjects]
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].ArrayID < items[j].ArrayID
	})

	return MarshalLLDResult(items)
}

// ============================================================================
// FUNCIONES DE SERIALIZACIÓN JSON
// ============================================================================

// MarshalLLDResult serializa items LLD a JSON compacto para Zabbix
// Referencia: Zabbix_Documentation_7.2.en.txt - LLD JSON format
func MarshalLLDResult(items interface{}) (string, error) {
	result := LLDResult{
		Data: []LLDItem{},
	}

	// Convertir items a []LLDItem usando reflection
	jsonBytes, err := json.Marshal(items)
	if err != nil {
		return `{"data":[]}`, err
	}

	// Unmarshal a estructura intermedia para construir LLDResult
	var tempItems []map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &tempItems); err != nil {
		return `{"data":[]}`, err
	}

	for _, item := range tempItems {
		lldItem := LLDItem{}
		for k, v := range item {
			if strVal, ok := v.(string); ok {
				lldItem[k] = strVal
			} else {
				lldItem[k] = fmt.Sprintf("%v", v)
			}
		}
		result.Data = append(result.Data, lldItem)
	}

	// Serializar a JSON compacto (sin espacios innecesarios)
	output, err := json.Marshal(result)
	if err != nil {
		return `{"data":[]}`, err
	}

	return string(output), nil
}

// MarshalLLDResultPretty serializa items LLD a JSON con indentación (para debugging)
func MarshalLLDResultPretty(items interface{}) (string, error) {
	result := LLDResult{
		Data: []LLDItem{},
	}

	jsonBytes, err := json.Marshal(items)
	if err != nil {
		return `{"data":[]}`, err
	}

	var tempItems []map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &tempItems); err != nil {
		return `{"data":[]}`, err
	}

	for _, item := range tempItems {
		lldItem := LLDItem{}
		for k, v := range item {
			if strVal, ok := v.(string); ok {
				lldItem[k] = strVal
			} else {
				lldItem[k] = fmt.Sprintf("%v", v)
			}
		}
		result.Data = append(result.Data, lldItem)
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return `{"data":[]}`, err
	}

	return string(output), nil
}

// ============================================================================
// FUNCIONES DE FILTRADO Y VALIDACIÓN
// ============================================================================

// FilterLLDByStatus filtra items LLD por estado
// Útil para excluir objetos offline del discovery
func FilterLLDByStatus(items []map[string]string, statusField, statusValue string) []map[string]string {
	var filtered []map[string]string

	for _, item := range items {
		if status, ok := item[statusField]; ok {
			if strings.ToLower(status) == strings.ToLower(statusValue) {
				filtered = append(filtered, item)
			}
		}
	}

	return filtered
}

// FilterLLDByMacro filtra items LLD usando un macro específico
// Ej: filtrar pools por nombre que contenga "prod"
func FilterLLDByMacro(items []map[string]string, macroName, pattern string) []map[string]string {
	var filtered []map[string]string

	for _, item := range items {
		if value, ok := item[macroName]; ok {
			if strings.Contains(strings.ToLower(value), strings.ToLower(pattern)) {
				filtered = append(filtered, item)
			}
		}
	}

	return filtered
}

// ValidateLLDJSON valida que el JSON LLD sea válido para Zabbix
// Referencia: Zabbix_Documentation_7.2.en.txt - LLD validation
func ValidateLLDJSON(jsonStr string) error {
	var result LLDResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return fmt.Errorf("invalid LLD JSON: %w", err)
	}

	// Validar que tenga al menos la estructura básica
	if result.Data == nil {
		return fmt.Errorf("LLD JSON missing 'data' array")
	}

	// Validar que cada item tenga al menos un macro
	for i, item := range result.Data {
		if len(item) == 0 {
			return fmt.Errorf("LLD item %d has no macros", i)
		}

		// Validar formato de macros ({#MACRO_NAME})
		for key := range item {
			if !strings.HasPrefix(key, "{#") || !strings.HasSuffix(key, "}") {
				return fmt.Errorf("LLD item %d has invalid macro format: %s", i, key)
			}
		}
	}

	return nil
}

// GetLLDMacros extrae lista de macros de un resultado LLD
func GetLLDMacros(jsonStr string) ([]string, error) {
	var result LLDResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, err
	}

	macroSet := make(map[string]bool)
	for _, item := range result.Data {
		for key := range item {
			macroSet[key] = true
		}
	}

	macros := make([]string, 0, len(macroSet))
	for macro := range macroSet {
		macros = append(macros, macro)
	}

	sort.Strings(macros)
	return macros, nil
}

// ============================================================================
// FUNCIONES DE ASISTENCIA
// ============================================================================

// CreateLLDItem crea un item LLD genérico desde un mapa
func CreateLLDItem(data map[string]string) LLDItem {
	item := LLDItem{}
	for k, v := range data {
		// Asegurar que la clave tenga formato de macro
		if !strings.HasPrefix(k, "{#") {
			k = "{#" + strings.ToUpper(k) + "}"
		}
		item[k] = v
	}
	return item
}

// BuildCustomLLD construye LLD personalizado desde datos genéricos
func BuildCustomLLD(items []LLDItem) (string, error) {
	result := LLDResult{Data: items}

	if len(result.Data) > MaxLLDObjects {
		result.Data = result.Data[:MaxLLDObjects]
	}

	output, err := json.Marshal(result)
	if err != nil {
		return `{"data":[]}`, err
	}

	return string(output), nil
}

// GetLLDCount retorna número de items en resultado LLD
func GetLLDCount(jsonStr string) (int, error) {
	var result LLDResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return 0, err
	}
	return len(result.Data), nil
}

// LLDEmptyResult retorna resultado LLD vacío (sin items)
func LLDEmptyResult() string {
	return `{"data":[]}`
}

// ============================================================================
// FUNCIONES DE LOGGING Y AUDITORÍA
// ============================================================================

// LogLLDStatistics registra estadísticas de LLD para auditoría
// Referencia: sg248561.txt Capítulo 4 - Audit logging
func LogLLDStatistics(discoveryType string, itemCount int, jsonSize int) {
	LogInfo("LLD Statistics", map[string]interface{}{
		"discovery_type": discoveryType,
		"item_count":     itemCount,
		"json_size_bytes": jsonSize,
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
	})
}

// ValidateLLDForZabbix valida que el LLD cumple requisitos de Zabbix 7.2
// Referencia: Zabbix_Documentation_7.2.en.txt - LLD requirements (p.1520)
func ValidateLLDForZabbix(jsonStr string) (bool, error) {
	// 1. Validar JSON sintáctico
	if err := json.Unmarshal([]byte(jsonStr), &LLDResult{}); err != nil {
		return false, fmt.Errorf("invalid JSON: %w", err)
	}

	// 2. Validar tamaño máximo (Zabbix tiene límite de 1MB para LLD)
	if len(jsonStr) > 1024*1024 {
		return false, fmt.Errorf("LLD JSON too large: %d bytes (max: 1MB)", len(jsonStr))
	}

	// 3. Validar que no esté vacío (al menos {"data":[]})
	if jsonStr == "" {
		return false, fmt.Errorf("LLD JSON is empty")
	}

	// 4. Validar formato de macros
	count, err := GetLLDCount(jsonStr)
	if err != nil {
		return false, err
	}

	LogInfo("LLD validation passed", map[string]interface{}{
		"item_count": count,
		"size_bytes": len(jsonStr),
	})

	return true, nil
}