#!/bin/bash
# ================================================================================
# IBM FlashSystem Monitor para Zabbix 7.2 - Script de Prueba de Conectividad
# ================================================================================
# ARCHIVO: scripts/test_connection.sh
# PROPÓSITO: Verificar conectividad y funcionalidad completa del monitor
# COMPATIBILIDAD: Red Hat 9 / AlmaLinux 9, Zabbix 7.2, Go 1.22+
# ================================================================================
#
# REFERENCIAS DOCUMENTALES:
# - sg248561.txt: IBM Storage Virtualize V8.7 Redbook (Capítulo 4 - Security)
# - svc_bkmap_cliguidebk (1).txt: CLI Command Reference
# - Zabbix_Documentation_7.2.en.txt: ExternalCheck specification (p.1518)
#
# USO:
#   sudo ./scripts/test_connection.sh <FLASHSYSTEM_IP>
#
# EJEMPLO:
#   sudo ./scripts/test_connection.sh 192.168.1.100
#
# ================================================================================

set -euo pipefail

# ================================================================================
# CONFIGURACIÓN GLOBAL
# ================================================================================

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Rutas de instalación
INSTALL_DIR="/opt/zabbix-ibm-flash"
CONFIG_DIR="${INSTALL_DIR}/config"
BIN_DIR="/usr/lib/zabbix/externalscripts"
SSH_KEY_PATH="${CONFIG_DIR}/id_ibm_flash"
ZABBIX_USER="zabbix"

# Contadores de pruebas
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# ================================================================================
# FUNCIONES DE LOGGING
# ================================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓ PASS]${NC} $1"
    ((TESTS_PASSED++))
    ((TESTS_TOTAL++))
}

log_warning() {
    echo -e "${YELLOW}[⚠ WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗ FAIL]${NC} $1"
    ((TESTS_FAILED++))
    ((TESTS_TOTAL++))
}

log_section() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
}

log_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
}

# ================================================================================
# FUNCIONES DE VALIDACIÓN
# ================================================================================

print_header() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  IBM FlashSystem - Test de Conectividad${NC}"
    echo -e "${GREEN}  Versión: 1.0.0                        ${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
}

print_usage() {
    echo "Uso: $0 <FLASHSYSTEM_IP>"
    echo ""
    echo "Argumentos:"
    echo "  FLASHSYSTEM_IP    IP de gestión del IBM FlashSystem"
    echo ""
    echo "Ejemplo:"
    echo "  sudo $0 192.168.1.100"
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root o con sudo"
        exit 1
    fi
}

check_ip_argument() {
    if [[ $# -lt 1 ]]; then
        log_error "Falta IP del FlashSystem"
        print_usage
        exit 1
    fi
    
    FLASHSYSTEM_IP="$1"
    
    # Validar formato de IP
    if [[ ! $FLASHSYSTEM_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_error "IP inválida: ${FLASHSYSTEM_IP}"
        exit 1
    fi
    
    log_info "IP del FlashSystem: ${FLASHSYSTEM_IP}"
}

# ================================================================================
# PRUEBAS DE CONECTIVIDAD
# ================================================================================

test_network_connectivity() {
    log_section "Prueba 1: Conectividad de Red"
    log_test "Verificando conectividad ICMP hacia ${FLASHSYSTEM_IP}..."
    
    if ping -c 3 -W 5 "${FLASHSYSTEM_IP}" &>/dev/null; then
        log_success "Conectividad ICMP verificada (3 paquetes)"
        
        # Mostrar estadísticas de ping
        ping -c 3 -W 5 "${FLASHSYSTEM_IP}" 2>&1 | tail -2
    else
        log_error "No hay conectividad ICMP hacia ${FLASHSYSTEM_IP}"
        log_warning "Posibles causas:"
        echo "  1. Firewall bloqueando ICMP"
        echo "  2. IP incorrecta"
        echo "  3. Storage apagado o en mantenimiento"
        echo "  4. Problema de ruteo de red"
        return 1
    fi
}

test_ssh_port() {
    log_section "Prueba 2: Puerto SSH"
    log_test "Verificando puerto SSH (22/tcp) en ${FLASHSYSTEM_IP}..."
    
    # Intentar con nc (netcat)
    if command -v nc &>/dev/null; then
        if nc -zv -w 5 "${FLASHSYSTEM_IP}" 22 &>/dev/null; then
            log_success "Puerto SSH 22/tcp accesible"
        else
            log_error "Puerto SSH 22/tcp NO accesible"
            log_warning "Posibles causas:"
            echo "  1. Firewall bloqueando puerto 22"
            echo "  2. Servicio SSH no activo en el storage"
            echo "  3. Puerto SSH personalizado (no es 22)"
            return 1
        fi
    # Intentar con timeout + bash
    elif command -v timeout &>/dev/null; then
        if timeout 5 bash -c "echo > /dev/tcp/${FLASHSYSTEM_IP}/22" &>/dev/null; then
            log_success "Puerto SSH 22/tcp accesible"
        else
            log_error "Puerto SSH 22/tcp NO accesible"
            return 1
        fi
    else
        log_warning "nc y timeout no disponibles, saltando prueba de puerto"
    fi
}

test_ssh_key_exists() {
    log_section "Prueba 3: Clave SSH"
    log_test "Verificando existencia de clave SSH en ${SSH_KEY_PATH}..."
    
    if [[ ! -f "${SSH_KEY_PATH}" ]]; then
        log_error "Clave SSH no existe: ${SSH_KEY_PATH}"
        log_warning "Ejecute el script de instalación primero:"
        echo "  sudo ./scripts/install.sh"
        return 1
    fi
    
    log_success "Clave SSH existe: ${SSH_KEY_PATH}"
    
    # Verificar permisos
    log_test "Verificando permisos de clave SSH..."
    KEY_PERMS=$(stat -c '%a' "${SSH_KEY_PATH}" 2>/dev/null)
    
    if [[ "${KEY_PERMS}" == "600" ]]; then
        log_success "Permisos de clave SSH correctos: ${KEY_PERMS}"
    else
        log_error "Permisos de clave SSH incorrectos: ${KEY_PERMS} (esperado: 600)"
        log_warning "Corregir con:"
        echo "  sudo chmod 600 ${SSH_KEY_PATH}"
        return 1
    fi
    
    # Verificar propietario
    log_test "Verificando propietario de clave SSH..."
    KEY_OWNER=$(stat -c '%U:%G' "${SSH_KEY_PATH}" 2>/dev/null)
    
    if [[ "${KEY_OWNER}" == "${ZABBIX_USER}:${ZABBIX_USER}" ]]; then
        log_success "Propietario de clave SSH correcto: ${KEY_OWNER}"
    else
        log_warning "Propietario de clave SSH: ${KEY_OWNER} (recomendado: ${ZABBIX_USER}:${ZABBIX_USER})"
    fi
    
    # Mostrar información de la clave
    log_test "Información de la clave SSH:"
    ssh-keygen -l -f "${SSH_KEY_PATH}.pub" 2>/dev/null || true
}

test_ssh_authentication() {
    log_section "Prueba 4: Autenticación SSH"
    log_test "Verificando autenticación SSH con clave..."
    
    # Intentar conexión SSH sin password
    if sudo -u ${ZABBIX_USER} ssh -i "${SSH_KEY_PATH}" \
        -o BatchMode=yes \
        -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout=10 \
        "zabbix_monitor@${FLASHSYSTEM_IP}" \
        "echo SSH_AUTH_SUCCESS" &>/dev/null; then
        
        log_success "Autenticación SSH exitosa"
        
    else
        log_error "Autenticación SSH fallida"
        log_warning "Posibles causas:"
        echo "  1. Clave pública no instalada en FlashSystem"
        echo "  2. Usuario zabbix_monitor no existe en FlashSystem"
        echo "  3. Permisos de clave incorrectos"
        echo "  4. SSH key no autorizada en el storage"
        echo ""
        log_warning "Para instalar la clave en FlashSystem:"
        echo "  1. Conectarse como superuser:"
        echo "     ssh superuser@${FLASHSYSTEM_IP}"
        echo ""
        echo "  2. Copiar contenido de clave pública:"
        echo "     cat ${SSH_KEY_PATH}.pub"
        echo ""
        echo "  3. Configurar usuario zabbix_monitor:"
        echo "     chuser -ssh_key \"<pegar_clave>\" zabbix_monitor"
        echo ""
        echo "  4. Verificar configuración:"
        echo "     lsuser -name zabbix_monitor"
        return 1
    fi
}

test_cli_command() {
    log_section "Prueba 5: Ejecución de Comando CLI"
    log_test "Ejecutando comando 'lssystem' en FlashSystem..."
    
    OUTPUT=$(sudo -u ${ZABBIX_USER} ssh -i "${SSH_KEY_PATH}" \
        -o BatchMode=yes \
        -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout=10 \
        "zabbix_monitor@${FLASHSYSTEM_IP}" \
        "lssystem -delim : -nohdr" 2>&1)
    
    EXIT_CODE=$?
    
    if [[ ${EXIT_CODE} -eq 0 ]] && [[ -n "${OUTPUT}" ]]; then
        log_success "Comando CLI ejecutado correctamente"
        
        # Parsear información del sistema
        SYSTEM_NAME=$(echo "${OUTPUT}" | cut -d':' -f1)
        SYSTEM_STATUS=$(echo "${OUTPUT}" | cut -d':' -f2)
        SYSTEM_VERSION=$(echo "${OUTPUT}" | cut -d':' -f3)
        
        log_info "Información del sistema:"
        echo "  Nombre:    ${SYSTEM_NAME}"
        echo "  Estado:    ${SYSTEM_STATUS}"
        echo "  Versión:   ${SYSTEM_VERSION}"
        
        if [[ "${SYSTEM_STATUS}" == "online" ]]; then
            log_success "Sistema está ONLINE"
        else
            log_warning "Sistema estado: ${SYSTEM_STATUS}"
        fi
    else
        log_error "Ejecución de comando CLI fallida (exit code: ${EXIT_CODE})"
        log_warning "Output:"
        echo "${OUTPUT}"
        return 1
    fi
}

test_zabbix_binary() {
    log_section "Prueba 6: Binario de Zabbix"
    log_test "Verificando binario ibm_flash_monitor..."
    
    if [[ ! -f "${BIN_DIR}/ibm_flash_monitor" ]]; then
        log_error "Binario no existe: ${BIN_DIR}/ibm_flash_monitor"
        log_warning "Ejecute el script de instalación primero:"
        echo "  sudo ./scripts/install.sh"
        return 1
    fi
    
    log_success "Binario existe: ${BIN_DIR}/ibm_flash_monitor"
    
    # Verificar permisos
    log_test "Verificando permisos del binario..."
    BIN_PERMS=$(stat -c '%a' "${BIN_DIR}/ibm_flash_monitor" 2>/dev/null)
    
    if [[ "${BIN_PERMS}" == "750" ]]; then
        log_success "Permisos del binario correctos: ${BIN_PERMS}"
    else
        log_warning "Permisos del binario: ${BIN_PERMS} (recomendado: 750)"
    fi
    
    # Verificar propietario
    log_test "Verificando propietario del binario..."
    BIN_OWNER=$(stat -c '%U:%G' "${BIN_DIR}/ibm_flash_monitor" 2>/dev/null)
    
    if [[ "${BIN_OWNER}" == "${ZABBIX_USER}:${ZABBIX_USER}" ]]; then
        log_success "Propietario del binario correcto: ${BIN_OWNER}"
    else
        log_warning "Propietario del binario: ${BIN_OWNER}"
    fi
    
    # Verificar tipo de archivo
    log_test "Verificando tipo de archivo..."
    file "${BIN_DIR}/ibm_flash_monitor"
}

test_zabbix_external_check() {
    log_section "Prueba 7: ExternalCheck de Zabbix"
    log_test "Ejecutando ibm_flash_monitor como ExternalCheck..."
    
    # Probar comando system_health
    OUTPUT=$(sudo -u ${ZABBIX_USER} "${BIN_DIR}/ibm_flash_monitor" \
        "${FLASHSYSTEM_IP}" \
        "system_health" 2>&1)
    
    EXIT_CODE=$?
    
    if [[ ${EXIT_CODE} -eq 0 ]] && [[ "${OUTPUT}" == "1" ]]; then
        log_success "ExternalCheck system_health exitoso: ${OUTPUT}"
    elif [[ ${EXIT_CODE} -eq 0 ]] && [[ "${OUTPUT}" == "0" ]]; then
        log_warning "ExternalCheck system_health: ${OUTPUT} (sistema offline)"
    else
        log_error "ExternalCheck system_health fallido (exit code: ${EXIT_CODE})"
        log_warning "Output: ${OUTPUT}"
        return 1
    fi
    
    # Probar comando de descubrimiento LLD
    log_test "Probando descubrimiento LLD (discover_pools)..."
    
    OUTPUT=$(sudo -u ${ZABBIX_USER} "${BIN_DIR}/ibm_flash_monitor" \
        "${FLASHSYSTEM_IP}" \
        "discover_pools" 2>&1)
    
    EXIT_CODE=$?
    
    if [[ ${EXIT_CODE} -eq 0 ]] && [[ "${OUTPUT}" =~ ^\{"data": ]]; then
        log_success "Descubrimiento LLD exitoso"
        
        # Contar pools descubiertos
        POOL_COUNT=$(echo "${OUTPUT}" | grep -o '"{#POOL_ID}"' | wc -l)
        log_info "Pools descubiertos: ${POOL_COUNT}"
        
        # Mostrar resumen (primeros 500 caracteres)
        log_info "Resumen del output:"
        echo "${OUTPUT}" | head -c 500
        echo "..."
    else
        log_error "Descubrimiento LLD fallido (exit code: ${EXIT_CODE})"
        log_warning "Output: ${OUTPUT}"
        return 1
    fi
}

test_config_files() {
    log_section "Prueba 8: Archivos de Configuración"
    log_test "Verificando archivos de configuración..."
    
    # Verificar zabbix.json
    if [[ -f "${CONFIG_DIR}/zabbix.json" ]]; then
        log_success "zabbix.json existe"
        
        # Validar JSON
        if command -v jq &>/dev/null; then
            if jq . "${CONFIG_DIR}/zabbix.json" &>/dev/null; then
                log_success "zabbix.json es JSON válido"
            else
                log_error "zabbix.json NO es JSON válido"
            fi
        fi
        
        # Verificar permisos
        CONFIG_PERMS=$(stat -c '%a' "${CONFIG_DIR}/zabbix.json" 2>/dev/null)
        if [[ "${CONFIG_PERMS}" == "640" ]]; then
            log_success "Permisos de zabbix.json correctos: ${CONFIG_PERMS}"
        else
            log_warning "Permisos de zabbix.json: ${CONFIG_PERMS} (recomendado: 640)"
        fi
    else
        log_error "zabbix.json no existe: ${CONFIG_DIR}/zabbix.json"
    fi
    
    # Verificar secrets.env
    if [[ -f "${CONFIG_DIR}/secrets.env" ]]; then
        log_success "secrets.env existe"
        
        # Verificar permisos (debe ser 600)
        SECRETS_PERMS=$(stat -c '%a' "${CONFIG_DIR}/secrets.env" 2>/dev/null)
        if [[ "${SECRETS_PERMS}" == "600" ]]; then
            log_success "Permisos de secrets.env correctos: ${SECRETS_PERMS}"
        else
            log_error "Permisos de secrets.env incorrectos: ${SECRETS_PERMS} (esperado: 600)"
        fi
    else
        log_error "secrets.env no existe: ${CONFIG_DIR}/secrets.env"
    fi
}

test_selinux() {
    log_section "Prueba 9: SELinux (Red Hat 9)"
    
    if ! command -v getenforce &>/dev/null; then
        log_warning "SELinux no disponible, saltando prueba"
        return 0
    fi
    
    SELINUX_STATUS=$(getenforce)
    log_info "Estado de SELinux: ${SELINUX_STATUS}"
    
    if [[ "${SELINUX_STATUS}" == "Disabled" ]]; then
        log_warning "SELinux deshabilitado"
        return 0
    fi
    
    # Verificar contexto del binario
    log_test "Verificando contexto SELinux del binario..."
    BIN_CONTEXT=$(ls -Z "${BIN_DIR}/ibm_flash_monitor" 2>/dev/null | awk '{print $1}')
    
    if [[ "${BIN_CONTEXT}" =~ zabbix_script_t ]]; then
        log_success "Contexto SELinux correcto: ${BIN_CONTEXT}"
    else
        log_warning "Contexto SELinux: ${BIN_CONTEXT} (recomendado: zabbix_script_t)"
        log_warning "Para corregir:"
        echo "  sudo restorecon -v ${BIN_DIR}/ibm_flash_monitor"
    fi
    
    # Verificar booleano de red
    log_test "Verificando booleano zabbix_can_network..."
    if command -v getsebool &>/dev/null; then
        NETWORK_BOOL=$(getsebool zabbix_can_network 2>/dev/null | awk '{print $3}')
        if [[ "${NETWORK_BOOL}" == "on" ]]; then
            log_success "Booleano zabbix_can_network: ${NETWORK_BOOL}"
        else
            log_warning "Booleano zabbix_can_network: ${NETWORK_BOOL} (recomendado: on)"
        fi
    fi
}

test_zabbix_server() {
    log_section "Prueba 10: Zabbix Server"
    log_test "Verificando estado de Zabbix Server..."
    
    if systemctl is-active --quiet zabbix-server; then
        log_success "Zabbix Server está activo"
        
        # Verificar configuración de ExternalScripts
        log_test "Verificando configuración de ExternalScripts..."
        if grep -q "^ExternalScripts=${BIN_DIR}" /etc/zabbix/zabbix_server.conf; then
            log_success "ExternalScripts configurado correctamente"
        else
            log_warning "ExternalScripts puede no estar configurado correctamente"
            grep "ExternalScripts" /etc/zabbix/zabbix_server.conf || true
        fi
        
        # Verificar Timeout
        log_test "Verificando Timeout de Zabbix..."
        TIMEOUT=$(grep "^Timeout=" /etc/zabbix/zabbix_server.conf 2>/dev/null | cut -d'=' -f2)
        if [[ -n "${TIMEOUT}" ]] && [[ "${TIMEOUT}" -ge 30 ]]; then
            log_success "Timeout de Zabbix: ${TIMEOUT}s"
        else
            log_warning "Timeout de Zabbix: ${TIMEOUT:-no configurado}s (recomendado: >=30)"
        fi
    else
        log_warning "Zabbix Server no está activo"
        log_warning "Para iniciar:"
        echo "  sudo systemctl start zabbix-server"
    fi
}

# ================================================================================
# RESUMEN FINAL
# ================================================================================

print_summary() {
    log_section "Resumen de Pruebas"
    
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  RESULTADOS                            ${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    echo -e "Total de pruebas:    ${TESTS_TOTAL}"
    echo -e "${GREEN}Pruebas pasadas:     ${TESTS_PASSED}${NC}"
    echo -e "${RED}Pruebas fallidas:    ${TESTS_FAILED}${NC}"
    echo ""
    
    if [[ ${TESTS_FAILED} -eq 0 ]]; then
        echo -e "${GREEN}========================================${NC}"
        echo -e "${GREEN}  ✓ TODAS LAS PRUEBAS PASARON          ${NC}"
        echo -e "${GREEN}========================================${NC}"
        echo ""
        log_info "El sistema está listo para producción"
        echo ""
        echo "Siguientes pasos:"
        echo "  1. Importar plantilla Zabbix"
        echo "  2. Crear host en Zabbix"
        echo "  3. Configurar macros"
        echo "  4. Verificar items en Monitoring → Latest Data"
        exit 0
    else
        echo -e "${RED}========================================${NC}"
        echo -e "${RED}  ✗ ALGUNAS PRUEBAS FALLARON           ${NC}"
        echo -e "${RED}========================================${NC}"
        echo ""
        log_warning "Revise los errores arriba y corríjalos antes de usar en producción"
        echo ""
        echo "Recursos de ayuda:"
        echo "  - docs/TROUBLESHOOTING.md"
        echo "  - docs/INSTALL_RHEL9.md"
        echo "  - docs/SECURITY.md"
        exit 1
    fi
}

# ================================================================================
# MANEJO DE SEÑALES
# ================================================================================

cleanup() {
    echo ""
    log_warning "Prueba interrumpida por el usuario"
    print_summary
    exit 1
}

trap cleanup SIGINT SIGTERM

# ================================================================================
# FUNCIÓN PRINCIPAL
# ================================================================================

main() {
    print_header
    
    # Validaciones iniciales
    check_root
    check_ip_argument "$@"
    
    # Ejecutar pruebas
    test_network_connectivity || true
    test_ssh_port || true
    test_ssh_key_exists || true
    test_ssh_authentication || true
    test_cli_command || true
    test_zabbix_binary || true
    test_zabbix_external_check || true
    test_config_files || true
    test_selinux || true
    test_zabbix_server || true
    
    # Imprimir resumen
    print_summary
}

# ================================================================================
# EJECUCIÓN
# ================================================================================

# Parsear argumentos
while getopts "h" opt; do
    case ${opt} in
        h )
            print_usage
            exit 0
            ;;
        \? )
            print_usage
            exit 1
            ;;
    esac
done

# Ejecutar pruebas
main "$@"