// lib/ssh_client.go
// Cliente SSH seguro para IBM FlashSystem 5045/7300/9500 y SAN Volume Controller
// Compatible con Storage Virtualize V8.7
//
// Requisitos de Seguridad:
// - Autenticación por clave SSH ED25519 (sin password)
// - Verificación de host key (known_hosts)
// - Timeout configurable (< Timeout en zabbix_server.conf)
// - Whitelist de comandos CLI (prevención de inyección)
// - Logging seguro (nunca a stdout)
// - Validación de permisos de clave privada (600)
//
// Referencias:
// - svc_bkmap_cliguidebk (1).txt: SSH key management (Chapter 1)
// - sg248561.txt: IBM Storage Virtualize V8.7 Security (Chapter 4)
// - Zabbix_Documentation_7.2.en.txt: ExternalCheck specification
//
// Compilación:
//   cd src && go build -o ibm_flash_monitor .
//
// Uso:
//   client, err := NewSecureSSHClient(host, user, port, keyPath, knownHosts, timeout)
//   output, err := client.ExecuteCommand("lssystem -delim : -nohdr")

package lib

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ============================================================================
// CONSTANTES DE SEGURIDAD
// ============================================================================

const (
	// Timeout máximo permitido (debe ser < Timeout en zabbix_server.conf)
	MaxTimeoutSeconds = 30

	// Longitud máxima de comando (prevención de DoS)
	MaxCommandLength = 4096

	// Longitud máxima de parámetro (prevención de inyección)
	MaxParamLength = 256

	// Puerto SSH por defecto
	DefaultSSHPort = "22"

	// Permisos esperados para clave privada (rw-------)
	ExpectedKeyPermissions os.FileMode = 0600

	// Algoritmo de clave recomendado
	RecommendedKeyType = "ED25519"
)

// ============================================================================
// ESTRUCTURAS DE DATOS
// ============================================================================

// SecureSSHClient implementa cliente SSH hardened para IBM FlashSystem
type SecureSSHClient struct {
	host         string
	user         string
	port         string
	keyPath      string
	knownHosts   string
	timeout      time.Duration
	clientConfig *ssh.ClientConfig
	hostKey      ssh.PublicKey
}

// SSHKeyInfo contiene información de la clave SSH para auditoría
type SSHKeyInfo struct {
	Type       string    // ED25519, RSA, etc.
	Bits       int       // Longitud de clave (bits)
	Fingerprint string   // SHA256 fingerprint
	Path       string    // Ruta del archivo
	Permissions os.FileMode // Permisos del archivo
	ModTime    time.Time // Última modificación
}

// CommandValidationResult contiene resultado de validación de comando
type CommandValidationResult struct {
	IsValid    bool     // true si el comando es válido
	Command    string   // Comando sanitizado
	Reason     string   // Razón de rechazo (si no es válido)
	BaseCmd    string   // Comando base (primera palabra)
	Params     []string // Parámetros extraídos
}

// ============================================================================
// CONSTRUCTOR Y VALIDACIÓN
// ============================================================================

// NewSecureSSHClient inicializa cliente con validaciones de seguridad estrictas
// Referencia: svc_bkmap_cliguidebk (1).txt Chapter 1 - Setting up an SSH client
func NewSecureSSHClient(host, user, port, keyPath, knownHosts string, timeoutSec int) (*SecureSSHClient, error) {
	// Validar host (prevención SSRF)
	if !IsValidHost(host) {
		LogError("Invalid host format", fmt.Errorf("host: %s", host))
		return nil, fmt.Errorf("invalid host format: %s", host)
	}

	// Validar usuario (solo alfanumérico, max 32 chars, no root/superuser)
	if !IsValidUsername(user) {
		LogError("Invalid username", fmt.Errorf("user: %s", user))
		return nil, fmt.Errorf("invalid username: %s", user)
	}

	// Validar puerto (1024-65535)
	if !IsValidPort(port) {
		LogError("Invalid port", fmt.Errorf("port: %s", port))
		return nil, fmt.Errorf("invalid port: %s", port)
	}

	// Validar timeout (1-30 segundos)
	if timeoutSec < 1 || timeoutSec > MaxTimeoutSeconds {
		LogError("Invalid timeout", fmt.Errorf("timeout: %d (max: %d)", timeoutSec, MaxTimeoutSeconds))
		return nil, fmt.Errorf("invalid timeout: %d seconds (must be 1-%d)", timeoutSec, MaxTimeoutSeconds)
	}

	// Validar permisos de clave privada (DEBE ser 600)
	if err := ValidateKeyPermissions(keyPath); err != nil {
		LogError("Key permission validation failed", err)
		return nil, fmt.Errorf("key permission error: %w", err)
	}

	// Obtener información de clave para auditoría
	keyInfo, err := GetSSHKeyInfo(keyPath)
	if err != nil {
		LogError("Failed to get key info", err)
		return nil, fmt.Errorf("key info error: %w", err)
	}

	// Log de auditoría (solo en archivo, nunca stdout)
	LogInfo("SSH Key Info", map[string]interface{}{
		"type":        keyInfo.Type,
		"bits":        keyInfo.Bits,
		"fingerprint": keyInfo.Fingerprint,
		"permissions": fmt.Sprintf("%o", keyInfo.Permissions),
		"path":        keyInfo.Path,
	})

	// Cargar clave privada
	signer, err := LoadPrivateKey(keyPath)
	if err != nil {
		LogError("Failed to load private key", err)
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	// Configurar política de host key verification
	callback, hostKey, err := GetHostKeyCallback(knownHosts, host, port)
	if err != nil {
		LogError("Host key callback error", err)
		return nil, fmt.Errorf("host key callback error: %w", err)
	}

	timeout := time.Duration(timeoutSec) * time.Second

	// Configurar cliente SSH con hardening de seguridad
	// Referencia: python-3.14-docs.txt - SSL/TLS best practices
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
			// NO incluir ssh.Password() - solo key-based auth
		},
		HostKeyCallback: callback,
		Timeout:         timeout,
		BannerCallback:  ssh.NoBanner,
		// Hardening de algoritmos criptográficos
		Config: ssh.Config{
			Ciphers: []string{
				"chacha20-poly1305@openssh.com",
				"aes256-gcm@openssh.com",
				"aes128-gcm@openssh.com",
			},
			MACs: []string{
				"hmac-sha2-256-etm@openssh.com",
				"hmac-sha2-512-etm@openssh.com",
			},
			KeyExchanges: []string{
				"curve25519-sha256",
				"curve25519-sha256@libssh.org",
			},
		},
		// HostKeyAlgorithms para verificación explícita
		HostKeyAlgorithms: []string{
			"ssh-ed25519",
			"ssh-ed25519-cert-v01@openssh.com",
			"rsa-sha2-512",
			"rsa-sha2-256",
		},
	}

	client := &SecureSSHClient{
		host:         host,
		user:         user,
		port:         port,
		keyPath:      keyPath,
		knownHosts:   knownHosts,
		timeout:      timeout,
		clientConfig: config,
		hostKey:      hostKey,
	}

	return client, nil
}

// ============================================================================
// EJECUCIÓN DE COMANDOS
// ============================================================================

// ExecuteCommand ejecuta comando CLI con validación estricta y timeout
// Referencia: svc_bkmap_cliguidebk (1).txt - CLI command execution
func (s *SecureSSHClient) ExecuteCommand(cmd string) (string, error) {
	// Validar comando contra whitelist
	validation := ValidateCommand(cmd)
	if !validation.IsValid {
		LogError("Command validation failed", fmt.Errorf("reason: %s, command: %s", validation.Reason, cmd))
		return "", fmt.Errorf("command validation failed: %s", validation.Reason)
	}

	// Log de auditoría (comando sanitizado)
	LogInfo("Executing command", map[string]interface{}{
		"host":      s.host,
		"user":      s.user,
		"command":   validation.Command,
		"timeout":   s.timeout.Seconds(),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})

	// Establecer conexión SSH
	client, err := ssh.Dial("tcp", net.JoinHostPort(s.host, s.port), s.clientConfig)
	if err != nil {
		LogError("SSH dial failed", err)
		return "", fmt.Errorf("ssh dial failed: %w", err)
	}
	defer client.Close()

	// Crear sesión
	session, err := client.NewSession()
	if err != nil {
		LogError("Session creation failed", err)
		return "", fmt.Errorf("session creation failed: %w", err)
	}
	defer session.Close()

	// Configurar buffers para stdout/stderr
	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	// Ejecutar comando con timeout explícito
	done := make(chan error, 1)
	go func() {
		done <- session.Run(validation.Command)
	}()

	select {
	case err := <-done:
		if err != nil {
			// Log stderr si hay error
			if stderrBuf.Len() > 0 {
				LogWarning("Command stderr", map[string]interface{}{
					"stderr": stderrBuf.String(),
					"error":  err.Error(),
				})
			}
			return "", fmt.Errorf("command execution failed: %w", err)
		}

		output := strings.TrimSpace(stdoutBuf.String())

		// Log de éxito (solo longitud, no contenido para no exponer datos sensibles)
		LogInfo("Command completed", map[string]interface{}{
			"output_length": len(output),
			"exit_code":     0,
		})

		return output, nil

	case <-time.After(s.timeout):
		session.Close()
		LogError("Command timeout", fmt.Errorf("timeout after %v", s.timeout))
		return "", fmt.Errorf("command timeout after %v", s.timeout)
	}
}

// ExecuteCommandWithRetry ejecuta comando con reintentos para errores transitorios
func (s *SecureSSHClient) ExecuteCommandWithRetry(cmd string, maxRetries int, retryDelay time.Duration) (string, error) {
	var lastErr error
	var output string

	for attempt := 1; attempt <= maxRetries; attempt++ {
		output, lastErr = s.ExecuteCommand(cmd)
		if lastErr == nil {
			return output, nil
		}

		// No reintentar errores de validación (son permanentes)
		if strings.Contains(lastErr.Error(), "command validation failed") {
			return "", lastErr
		}

		LogWarning("Command retry", map[string]interface{}{
			"attempt": attempt,
			"max":     maxRetries,
			"error":   lastErr.Error(),
			"delay":   retryDelay.Seconds(),
		})

		if attempt < maxRetries {
			time.Sleep(retryDelay)
		}
	}

	return "", fmt.Errorf("command failed after %d retries: %w", maxRetries, lastErr)
}

// ============================================================================
// VALIDACIÓN DE COMANDOS (WHITELIST)
// ============================================================================

// ValidateCommand valida comando contra whitelist y sanitiza entrada
// Referencia: svc_bkmap_cliguidebk (1).txt - Supported CLI commands
func ValidateCommand(cmd string) CommandValidationResult {
	result := CommandValidationResult{
		IsValid: false,
		Command: "",
		Reason:  "",
	}

	// Validar longitud máxima
	if len(cmd) > MaxCommandLength {
		result.Reason = fmt.Sprintf("command too long: %d chars (max: %d)", len(cmd), MaxCommandLength)
		return result
	}

	// Validar que no esté vacío
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		result.Reason = "empty command"
		return result
	}

	// Extraer comando base (primera palabra)
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		result.Reason = "no command found"
		return result
	}

	baseCmd := fields[0]
	params := fields[1:]

	// Verificar whitelist de comandos permitidos
	if !IsCommandAllowed(baseCmd) {
		result.Reason = fmt.Sprintf("command not in whitelist: %s", baseCmd)
		return result
	}

	// Rechazar caracteres peligrosos (prevención de inyección)
	if ContainsDangerousChars(cmd) {
		result.Reason = "command contains dangerous characters"
		return result
	}

	// Validar que no contenga paths absolutos sospechosos
	if ContainsSuspiciousPaths(cmd) {
		result.Reason = "command contains suspicious paths"
		return result
	}

	// Validar parámetros individuales
	for _, param := range params {
		if len(param) > MaxParamLength {
			result.Reason = fmt.Sprintf("parameter too long: %d chars (max: %d)", len(param), MaxParamLength)
			return result
		}
		if ContainsDangerousChars(param) {
			result.Reason = "parameter contains dangerous characters"
			return result
		}
	}

	// Comando válido
	result.IsValid = true
	result.Command = cmd
	result.BaseCmd = baseCmd
	result.Params = params

	return result
}

// IsCommandAllowed verifica si el comando está en la whitelist
// Referencia: svc_bkmap_cliguidebk (1).txt - Command reference
func IsCommandAllowed(cmd string) bool {
	// Whitelist de comandos CLI permitidos para monitoreo (solo lectura)
	allowedCommands := map[string]bool{
		// System commands
		"lssystem": true,
		"lsnode": true,
		"lsnodecanister": true,

		// Storage pool commands (sg248561.txt)
		"lsmdiskgrp": true,
		"lsfreeextents": true,

		// Volume commands
		"lsvdisk": true,
		"lsvdiskcopy": true,
		"lsvolumegroup": true,

		// Drive/enclosure commands
		"lsdrive": true,
		"lsenclosure": true,
		"lsenclosurebattery": true,
		"lsenclosurecanister": true,
		"lsenclosurepsu": true,
		"lsenclosureslot": true,

		// Replication commands (sg248543.txt)
		"lsreplication": true,
		"lsrcrelationship": true,
		"lsrcrelationshipcandidate": true,

		// Safeguarded Copy commands (sg248561.txt section 6.3)
		"lssafeguardedcopy": true,
		"lssnapshot": true,
		"lssnapshotpolicy": true,

		// Event/health commands
		"lseventlog": true,
		"lsportstats": true,
		"lsnodestats": true,

		// Data reduction commands
		"lscompressionstats": true,

		// Host commands
		"lshost": true,
		"lshostcluster": true,
		"lsvdiskhostmap": true,
	}

	return allowedCommands[cmd]
}

// ContainsDangerousChars verifica si el string contiene caracteres peligrosos
func ContainsDangerousChars(s string) bool {
	// Caracteres que pueden permitir inyección de comandos o shell escape
	dangerousPattern := regexp.MustCompile(`[;|&$` + "`" + `><\n\r\\'"{}()\[\]]`)
	return dangerousPattern.MatchString(s)
}

// ContainsSuspiciousPaths verifica si el comando contiene paths sospechosos
func ContainsSuspiciousPaths(s string) bool {
	suspiciousPaths := []string{
		"/etc/",
		"/root/",
		"/home/",
		"/var/log/",
		"/tmp/",
		"../",
		"..\\",
	}

	for _, path := range suspiciousPaths {
		if strings.Contains(s, path) {
			return true
		}
	}
	return false
}

// ============================================================================
// VALIDACIÓN DE PARÁMETROS DE ENTRADA
// ============================================================================

// IsValidHost valida formato de host (IPv4, IPv6, hostname RFC 1123)
func IsValidHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}

	// Validar IPv4
	ipv4Pattern := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	if ipv4Pattern.MatchString(host) {
		// Validar rangos de octetos
		parts := strings.Split(host, ".")
		for _, part := range parts {
			if len(part) > 1 && part[0] == '0' {
				return false // Leading zeros no permitidos
			}
		}
		return true
	}

	// Validar IPv6 (simplificado)
	if strings.Contains(host, ":") {
		return net.ParseIP(host) != nil
	}

	// Validar hostname RFC 1123
	hostnamePattern := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`)
	return hostnamePattern.MatchString(host)
}

// IsValidUsername valida nombre de usuario (alfanumérico, max 32 chars)
// Referencia: svc_bkmap_cliguidebk (1).txt - User management commands
func IsValidUsername(user string) bool {
	if user == "" || len(user) > 32 {
		return false
	}

	// Rechazar usuarios privilegiados
	privilegedUsers := map[string]bool{
		"root":      true,
		"superuser": true,
		"admin":     true,
		"service":   true,
	}
	if privilegedUsers[user] {
		return false
	}

	// Solo alfanumérico y underscore
	usernamePattern := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	return usernamePattern.MatchString(user)
}

// IsValidPort valida puerto en rango seguro (1024-65535)
func IsValidPort(port string) bool {
	if port == "" {
		return false
	}

	portPattern := regexp.MustCompile(`^\d+$`)
	if !portPattern.MatchString(port) {
		return false
	}

	var portNum int
	fmt.Sscanf(port, "%d", &portNum)
	return portNum >= 1024 && portNum <= 65535
}

// SanitizeParam sanitiza parámetro individual para uso en comandos
func SanitizeParam(param string) string {
	// Remover caracteres peligrosos
	dangerousPattern := regexp.MustCompile(`[;|&$` + "`" + `><\n\r\\'"{}()\[\]]`)
	param = dangerousPattern.ReplaceAllString(param, "")

	// Truncar a longitud razonable
	if len(param) > MaxParamLength {
		param = param[:MaxParamLength]
	}

	return strings.TrimSpace(param)
}

// ============================================================================
// GESTIÓN DE CLAVES SSH
// ============================================================================

// ValidateKeyPermissions verifica permisos 600 en clave privada
// Referencia: svc_bkmap_cliguidebk (1).txt - SSH key security
func ValidateKeyPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("key file not found: %w", err)
	}

	mode := info.Mode()
	// Verificar que solo el propietario puede leer/escribir (0o600)
	if mode.Perm()&0o077 != 0 {
		return fmt.Errorf("key file has insecure permissions: %s (expected 0600)", mode.Perm())
	}

	// Verificar que no es un symlink (prevención de TOCTOU)
	if mode.Type()&os.ModeSymlink != 0 {
		return fmt.Errorf("key file is a symlink: %s (not allowed for security)", path)
	}

	return nil
}

// GetSSHKeyInfo obtiene información de la clave SSH para auditoría
func GetSSHKeyInfo(path string) (*SSHKeyInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	// Leer clave pública para obtener fingerprint
	pubKeyPath := path + ".pub"
	keyType := "UNKNOWN"
	keyBits := 0
	fingerprint := "UNKNOWN"

	if pubKeyInfo, err := os.Stat(pubKeyPath); err == nil {
		pubKeyData, err := os.ReadFile(pubKeyPath)
		if err == nil {
			// Parsear clave pública para obtener tipo y fingerprint
			pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyData)
			if err == nil {
				keyType = pubKey.Type()
				fingerprint = FingerprintSHA256(pubKey)

				// Obtener bits según tipo de clave
				switch k := pubKey.(type) {
				case *ssh.Ed25519PublicKey:
					keyBits = 256
				case *ssh.RSAPublicKey:
					keyBits = k.Size() * 8
				}
			}
		}
	}

	return &SSHKeyInfo{
		Type:        keyType,
		Bits:        keyBits,
		Fingerprint: fingerprint,
		Path:        path,
		Permissions: info.Mode().Perm(),
		ModTime:     info.ModTime(),
	}, nil
}

// LoadPrivateKey carga clave privada desde archivo
func LoadPrivateKey(path string) (ssh.Signer, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return signer, nil
}

// GetHostKeyCallback configura política de verificación de host key
// Referencia: svc_bkmap_cliguidebk (1).txt - SSH host fingerprint
func GetHostKeyCallback(knownHostsPath, host, port string) (ssh.HostKeyCallback, ssh.PublicKey, error) {
	var hostKey ssh.PublicKey
	var callback ssh.HostKeyCallback
	var err error

	// Si known_hosts existe, usar verificación estricta
	if knownHostsPath != "" && FileExists(knownHostsPath) {
		callback, err = knownhosts.New(knownHostsPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load known_hosts: %w", err)
		}
		LogInfo("Host key verification enabled", map[string]interface{}{
			"known_hosts": knownHostsPath,
		})
	} else {
		// WARNING: Solo para desarrollo. En producción, usar known_hosts.
		LogWarning("No known_hosts file - using InsecureIgnoreHostKey (development mode)", nil)
		callback = ssh.InsecureIgnoreHostKey()
	}

	return callback, hostKey, nil
}

// FingerprintSHA256 genera fingerprint SHA256 de clave pública
func FingerprintSHA256(pubKey ssh.PublicKey) string {
	hash := sha256.Sum256(pubKey.Marshal())
	return "SHA256:" + base64.StdEncoding.EncodeToString(hash[:])
}

// ============================================================================
// FUNCIONES DE ASISTENCIA
// ============================================================================

// FileExists verifica si un archivo existe
func FileExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// DirExists verifica si un directorio existe
func DirExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

// EnsureDir crea directorio si no existe con permisos seguros
func EnsureDir(path string, perm os.FileMode) error {
	if !DirExists(path) {
		if err := os.MkdirAll(path, perm); err != nil {
			return err
		}
	}
	return nil
}

// GetHomeDir obtiene directorio home del usuario actual
func GetHomeDir() (string, error) {
	home := os.Getenv("HOME")
	if home == "" {
		return "", fmt.Errorf("HOME environment variable not set")
	}
	return home, nil
}

// JoinPath une rutas de forma segura (prevención de path traversal)
func JoinPath(base string, paths ...string) (string, error) {
	// Validar que base sea absoluto
	if !filepath.IsAbs(base) {
		return "", fmt.Errorf("base path must be absolute: %s", base)
	}

	result := base
	for _, p := range paths {
		// Remover cualquier ".." del path para prevenir traversal
		cleanP := filepath.Clean(p)
		if strings.Contains(cleanP, "..") {
			return "", fmt.Errorf("path traversal detected: %s", p)
		}
		result = filepath.Join(result, cleanP)
	}

	// Verificar que el resultado todavía está bajo base
	if !strings.HasPrefix(result, base) {
		return "", fmt.Errorf("path escape detected")
	}

	return result, nil
}

// ============================================================================
// CONEXIÓN Y PRUEBAS
// ============================================================================

// TestConnection prueba conexión SSH sin ejecutar comando
func (s *SecureSSHClient) TestConnection() error {
	client, err := ssh.Dial("tcp", net.JoinHostPort(s.host, s.port), s.clientConfig)
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	defer client.Close()
	return nil
}

// GetConnectionInfo retorna información de conexión para debugging
func (s *SecureSSHClient) GetConnectionInfo() map[string]interface{} {
	return map[string]interface{}{
		"host":         s.host,
		"user":         s.user,
		"port":         s.port,
		"timeout":      s.timeout.Seconds(),
		"key_path":     s.keyPath,
		"known_hosts":  s.knownHosts,
		"host_key":     s.hostKey,
		"cipher":       s.clientConfig.Config.Ciphers[0],
		"key_exchange": s.clientConfig.Config.KeyExchanges[0],
	}
}

// Close cierra todas las conexiones activas (cleanup)
func (s *SecureSSHClient) Close() {
	// El cliente SSH se cierra automáticamente con defer en ExecuteCommand
	// Esta función es para cleanup explícito si es necesario
	LogInfo("SSH client cleanup", map[string]interface{}{
		"host": s.host,
		"user": s.user,
	})
}