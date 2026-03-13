#!/bin/bash
# ================================================================================
# IBM FlashSystem Monitor para Zabbix 7.2 - Script de Instalación
# ================================================================================
# ARCHIVO: scripts/install.sh
# PROPÓSITO: Automatizar instalación completa del monitor IBM FlashSystem
# COMPATIBILIDAD: Red Hat 9 / AlmaLinux 9, Zabbix 7.2, Go 1.22+
# ================================================================================
#
# REFERENCIAS DOCUMENTALES:
# - sg248561.txt: IBM Storage Virtualize V8.7 Redbook (Capítulo 4 - Security)
# - svc_bkmap_cliguidebk (1).txt: CLI Command Reference
# - Zabbix_Documentation_7.2.en.txt: ExternalCheck specification (p.1518)
#
# REQUISITOS DE SEGURIDAD:
# - Ejecutar como root o con sudo
# - Usuario zabbix debe existir
# - Go instalado para compilación
# - SELinux Enforcing soportado
#
# USO:
#   sudo ./scripts/install.sh
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
NC='\033[0m' # No Color

# Rutas de instalación
INSTALL_DIR="/opt/zabbix-ibm-flash"
CONFIG_DIR="${INSTALL_DIR}/config"
LOG_DIR="${INSTALL_DIR}/logs"
SRC_DIR="${INSTALL_DIR}/src"
BIN_DIR="/usr/lib/zabbix/externalscripts"
TEMPLATE_DIR="${INSTALL_DIR}/templates"
DOC_DIR="${INSTALL_DIR}/docs"

# Archivos de configuración
ZABBIX_CONFIG="${CONFIG_DIR}/zabbix.json"
SECRETS_CONFIG="${CONFIG_DIR}/secrets.env"
SSH_KEY_PATH="${CONFIG_DIR}/id_ibm_flash"
KNOWN_HOSTS_PATH="${CONFIG_DIR}/known_hosts"

# Usuario y grupo
ZABBIX_USER="zabbix"
ZABBIX_GROUP="zabbix"

# Versión del proyecto
PROJECT_VERSION="1.0.0"
PROJECT_NAME="IBM FlashSystem Monitor"

# ================================================================================
# FUNCIONES DE LOGGING
# ================================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

# ================================================================================
# FUNCIONES DE VALIDACIÓN
# ================================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root o con sudo"
        exit 1
    fi
}

check_zabbix_user() {
    if ! id "${ZABBIX_USER}" &>/dev/null; then
        log_error "Usuario '${ZABBIX_USER}' no existe. Instale Zabbix primero."
        exit 1
    fi
    log_info "Usuario ${ZABBIX_USER} verificado"
}

check_go_installed() {
    if ! command -v go &>/dev/null; then
        log_error "Go no está instalado. Instale Go 1.22+ primero."
        log_info "Para instalar: sudo dnf install -y golang"
        exit 1
    fi
    
    GO_VERSION=$(go version | awk '{print $3}')
    log_info "Go versión ${GO_VERSION} detectado"
}

check_zabbix_server() {
    if ! systemctl is-active --quiet zabbix-server; then
        log_warning "Zabbix Server no está activo. ¿Está seguro de continuar?"
        read -p "Presione Enter para continuar o Ctrl+C para cancelar..."
    fi
    log_info "Zabbix Server verificado"
}

check_selinux() {
    if command -v getenforce &>/dev/null; then
        SELINUX_STATUS=$(getenforce)
        log_info "SELinux status: ${SELINUX_STATUS}"
        if [[ "${SELINUX_STATUS}" == "Enforcing" ]]; then
            log_info "SELinux Enforcing detectado - configurando políticas"
        fi
    fi
}

# ================================================================================
# FUNCIONES DE INSTALACIÓN
# ================================================================================

create_directories() {
    log_section "Creando estructura de directorios"
    
    mkdir -p "${INSTALL_DIR}"/{bin,config,logs,templates,docs,src/lib}
    mkdir -p "${BIN_DIR}"
    
    chown -R ${ZABBIX_USER}:${ZABBIX_GROUP} "${INSTALL_DIR}"
    chmod 750 "${INSTALL_DIR}"
    chmod 750 "${INSTALL_DIR}"/{bin,config,logs,templates,docs,src}
    
    log_success "Directorios creados en ${INSTALL_DIR}"
}

compile_go_binary() {
    log_section "Compilando binario Go"
    
    cd "${SRC_DIR}"
    
    # Inicializar módulo Go si no existe
    if [[ ! -f "go.mod" ]]; then
        log_info "Inicializando módulo Go..."
        go mod init zabbix-ibm-flash
    fi
    
    # Descargar dependencias
    log_info "Descargando dependencias Go..."
    go mod tidy
    go mod download
    
    # Compilar binario estático para Linux amd64
    log_info "Compilando binario..."
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ibm_flash_monitor .
    
    # Verificar binario
    if [[ ! -f "ibm_flash_monitor" ]]; then
        log_error "Compilación fallida"
        exit 1
    fi
    
    # Copiar a directorio de ExternalScripts de Zabbix
    log_info "Instalando binario en ${BIN_DIR}..."
    cp ibm_flash_monitor "${BIN_DIR}/"
    chown ${ZABBIX_USER}:${ZABBIX_GROUP} "${BIN_DIR}/ibm_flash_monitor"
    chmod 750 "${BIN_DIR}/ibm_flash_monitor"
    
    log_success "Binario compilado e instalado: ${BIN_DIR}/ibm_flash_monitor"
    
    # Verificar binario
    file "${BIN_DIR}/ibm_flash_monitor"
}

create_config_files() {
    log_section "Creando archivos de configuración"
    
    # Crear zabbix.json desde plantilla
    if [[ ! -f "${ZABBIX_CONFIG}" ]]; then
        log_info "Creando zabbix.json..."
        if [[ -f "${CONFIG_DIR}/zabbix.json.example" ]]; then
            cp "${CONFIG_DIR}/zabbix.json.example" "${ZABBIX_CONFIG}"
        else
            log_warning "zabbix.json.example no encontrado, creando configuración por defecto"
            cat > "${ZABBIX_CONFIG}" << 'EOF'
{
  "storage": {
    "default_timeout": 25,
    "ssh_port": 22,
    "ssh_user": "zabbix_monitor",
    "allowed_commands": ["lssystem", "lsmdiskgrp", "lsvdisk", "lsdrive", "lsenclosure"]
  },
  "zabbix": {
    "lld_refresh_interval": 3600,
    "external_script_path": "/usr/lib/zabbix/externalscripts"
  },
  "logging": {
    "level": "INFO",
    "file_path": "/opt/zabbix-ibm-flash/logs/ibm_flash_monitor.log",
    "max_file_size_mb": 50,
    "backup_count": 5
  },
  "security": {
    "require_known_hosts": true,
    "reject_dangerous_chars": true,
    "max_command_length": 4096
  }
}
EOF
        fi
        chown root:${ZABBIX_GROUP} "${ZABBIX_CONFIG}"
        chmod 640 "${ZABBIX_CONFIG}"
        log_success "zabbix.json creado"
    else
        log_warning "zabbix.json ya existe, saltando creación"
    fi
    
    # Crear secrets.env desde plantilla
    if [[ ! -f "${SECRETS_CONFIG}" ]]; then
        log_info "Creando secrets.env..."
        if [[ -f "${CONFIG_DIR}/secrets.env.example" ]]; then
            cp "${CONFIG_DIR}/secrets.env.example" "${SECRETS_CONFIG}"
        else
            log_warning "secrets.env.example no encontrado, creando configuración por defecto"
            cat > "${SECRETS_CONFIG}" << EOF
# IBM FlashSystem Monitor - Secrets Configuration
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# WARNING: Protect this file! Permissions must be 600

SSH_KEY_PATH=${SSH_KEY_PATH}
SSH_KNOWN_HOSTS_PATH=${KNOWN_HOSTS_PATH}
FLASHSYSTEM_USER=zabbix_monitor
SSH_PORT=22
SSH_TIMEOUT=25
LOG_FILE_PATH=${LOG_DIR}/ibm_flash_monitor.log
LOG_LEVEL=INFO
EOF
        fi
        chown root:${ZABBIX_GROUP} "${SECRETS_CONFIG}"
        chmod 600 "${SECRETS_CONFIG}"
        log_success "secrets.env creado (EDITE CON VALORES REALES)"
    else
        log_warning "secrets.env ya existe, saltando creación"
    fi
}

generate_ssh_key() {
    log_section "Generando clave SSH ED25519"
    
    if [[ -f "${SSH_KEY_PATH}" ]]; then
        log_warning "Clave SSH ya existe en ${SSH_KEY_PATH}"
        read -p "¿Regenerar clave? (s/N): " REGENERATE
        if [[ "${REGENERATE}" != "s" && "${REGENERATE}" != "S" ]]; then
            log_info "Manteniendo clave existente"
            return 0
        fi
    fi
    
    # Generar clave como usuario zabbix
    log_info "Generando clave ED25519 para usuario ${ZABBIX_USER}..."
    sudo -u ${ZABBIX_USER} ssh-keygen -t ed25519 \
        -f "${SSH_KEY_PATH}" \
        -N "" \
        -C "zabbix@$(hostname)-ibm-flash"
    
    # Verificar permisos
    chmod 600 "${SSH_KEY_PATH}"
    chown ${ZABBIX_USER}:${ZABBIX_GROUP} "${SSH_KEY_PATH}"
    chmod 644 "${SSH_KEY_PATH}.pub"
    chown ${ZABBIX_USER}:${ZABBIX_GROUP} "${SSH_KEY_PATH}.pub"
    
    # Verificar clave
    log_info "Verificando clave generada..."
    ssh-keygen -l -f "${SSH_KEY_PATH}.pub"
    
    log_success "Clave SSH generada: ${SSH_KEY_PATH}"
    log_warning "⚠️  INSTALE LA CLAVE PÚBLICA EN EL FLASHSYSTEM:"
    echo ""
    echo "  sudo -u ${ZABBIX_USER} ssh-copy-id -i ${SSH_KEY_PATH}.pub zabbix_monitor@<FLASHSYSTEM_IP>"
    echo ""
}

configure_selinux() {
    log_section "Configurando SELinux (Red Hat 9)"
    
    if ! command -v getenforce &>/dev/null; then
        log_warning "SELinux no disponible, saltando configuración"
        return 0
    fi
    
    SELINUX_STATUS=$(getenforce)
    if [[ "${SELINUX_STATUS}" == "Disabled" ]]; then
        log_info "SELinux deshabilitado, saltando configuración"
        return 0
    fi
    
    log_info "Configurando políticas SELinux..."
    
    # Instalar herramientas SELinux si no existen
    if ! command -v semanage &>/dev/null; then
        log_info "Instalando herramientas SELinux..."
        dnf install -y policycoreutils-python-utils
    fi
    
    # Configurar contexto para ExternalScripts
    log_info "Configurando contexto para ${BIN_DIR}..."
    semanage fcontext -a -t zabbix_script_t "${BIN_DIR}/ibm_flash_monitor" 2>/dev/null || true
    restorecon -v "${BIN_DIR}/ibm_flash_monitor"
    
    # Configurar contexto para configuración
    log_info "Configurando contexto para ${CONFIG_DIR}..."
    semanage fcontext -a -t zabbix_var_run_t "${CONFIG_DIR}(/.*)?" 2>/dev/null || true
    restorecon -Rv "${CONFIG_DIR}"
    
    # Configurar contexto para logs
    log_info "Configurando contexto para ${LOG_DIR}..."
    semanage fcontext -a -t zabbix_log_t "${LOG_DIR}(/.*)?" 2>/dev/null || true
    restorecon -Rv "${LOG_DIR}"
    
    # Permitir conexión SSH saliente
    log_info "Habilitando conexión SSH saliente para Zabbix..."
    setsebool -P zabbix_can_network on 2>/dev/null || true
    
    # Verificar configuración
    log_info "Verificando contextos SELinux..."
    ls -Z "${BIN_DIR}/ibm_flash_monitor" 2>/dev/null || true
    
    log_success "SELinux configurado"
}

configure_zabbix_server() {
    log_section "Configurando Zabbix Server"
    
    ZABBIX_CONF="/etc/zabbix/zabbix_server.conf"
    
    if [[ ! -f "${ZABBIX_CONF}" ]]; then
        log_error "Archivo de configuración de Zabbix no encontrado: ${ZABBIX_CONF}"
        exit 1
    fi
    
    # Verificar ExternalScripts
    log_info "Verificando configuración de ExternalScripts..."
    if ! grep -q "^ExternalScripts=" "${ZABBIX_CONF}"; then
        log_info "Agregando ExternalScripts a configuración..."
        echo "ExternalScripts=${BIN_DIR}" >> "${ZABBIX_CONF}"
    else
        EXTERNAL_SCRIPTS=$(grep "^ExternalScripts=" "${ZABBIX_CONF}" | cut -d'=' -f2)
        if [[ "${EXTERNAL_SCRIPTS}" != "${BIN_DIR}" ]]; then
            log_warning "ExternalScripts apunta a: ${EXTERNAL_SCRIPTS}"
            log_warning "Se recomienda: ${BIN_DIR}"
        fi
    fi
    
    # Verificar Timeout
    log_info "Verificando Timeout..."
    if ! grep -q "^Timeout=" "${ZABBIX_CONF}"; then
        log_info "Agregando Timeout=30 a configuración..."
        echo "Timeout=30" >> "${ZABBIX_CONF}"
    else
        TIMEOUT=$(grep "^Timeout=" "${ZABBIX_CONF}" | cut -d'=' -f2)
        if [[ "${TIMEOUT}" -lt 30 ]]; then
            log_warning "Timeout actual (${TIMEOUT}s) es menor que 30s"
            log_warning "Se recomienda aumentar para operaciones SSH"
        fi
    fi
    
    # Validar configuración
    log_info "Validando configuración de Zabbix..."
    if zabbix_server -T &>/dev/null; then
        log_success "Configuración de Zabbix válida"
    else
        log_warning "Validación de Zabbix falló, verifique manualmente"
    fi
    
    # Recargar configuración
    log_info "Recargando configuración de Zabbix Server..."
    if systemctl is-active --quiet zabbix-server; then
        zabbix_server -R config_cache_reload 2>/dev/null || true
        log_success "Configuración recargada"
    else
        log_warning "Zabbix Server no está activo, inícielo manualmente"
    fi
}

copy_templates() {
    log_section "Copiando plantillas Zabbix"
    
    if [[ -d "${TEMPLATE_DIR}" ]]; then
        log_info "Plantillas ya existen en ${TEMPLATE_DIR}"
    else
        mkdir -p "${TEMPLATE_DIR}"
        log_info "Directorio de plantillas creado"
    fi
    
    # Copiar plantilla YAML si existe
    if [[ -f "${SRC_DIR}/../templates/zabbix_template_ibm_flashsystem_5045.yaml" ]]; then
        cp "${SRC_DIR}/../templates/zabbix_template_ibm_flashsystem_5045.yaml" "${TEMPLATE_DIR}/"
        log_success "Plantilla YAML copiada"
    else
        log_warning "Plantilla YAML no encontrada, deberá importarla manualmente"
    fi
}

copy_documentation() {
    log_section "Copiando documentación"
    
    if [[ -d "${DOC_DIR}" ]]; then
        log_info "Documentación ya existe en ${DOC_DIR}"
    else
        mkdir -p "${DOC_DIR}"
        log_info "Directorio de documentación creado"
    fi
    
    # Copiar archivos de documentación si existen
    for doc in INSTALL_RHEL9.md SECURITY.md TROUBLESHOOTING.md COMMANDS_REFERENCE.md METRICS_REFERENCE.md; do
        if [[ -f "${SRC_DIR}/../docs/${doc}" ]]; then
            cp "${SRC_DIR}/../docs/${doc}" "${DOC_DIR}/"
        fi
    done
    
    log_success "Documentación copiada"
}

test_installation() {
    log_section "Probando instalación"
    
    log_info "Probando ejecución del binario..."
    if sudo -u ${ZABBIX_USER} "${BIN_DIR}/ibm_flash_monitor" --help &>/dev/null; then
        log_success "Binario ejecutable correctamente"
    else
        log_warning "Binario no responde a --help (puede ser normal)"
    fi
    
    log_info "Probando permisos de archivos..."
    stat -c '%a %U:%G %n' "${BIN_DIR}/ibm_flash_monitor"
    stat -c '%a %U:%G %n' "${ZABBIX_CONFIG}"
    stat -c '%a %U:%G %n' "${SECRETS_CONFIG}"
    stat -c '%a %U:%G %n' "${SSH_KEY_PATH}" 2>/dev/null || true
    
    log_info "Probando conectividad de red..."
    if command -v nc &>/dev/null; then
        log_info "Prueba de puerto SSH (requiere IP de FlashSystem)..."
        log_warning "Configure la IP del FlashSystem y ejecute:"
        echo ""
        echo "  nc -zv <FLASHSYSTEM_IP> 22"
        echo ""
    fi
    
    log_success "Pruebas completadas"
}

print_next_steps() {
    log_section "Siguientes Pasos"
    
    cat << EOF

${GREEN}========================================${NC}
${GREEN}  INSTALACIÓN COMPLETADA EXITOSAMENTE  ${NC}
${GREEN}========================================${NC}

${BLUE}1. CONFIGURAR FLASHSYSTEM:${NC}
   Conéctese al FlashSystem y cree el usuario de monitoreo:
   
   ssh superuser@<FLASHSYSTEM_IP>
   > mkuser -name zabbix_monitor -password "<password_temporal>" -usergrp_id 4
   > chuser -ssh_key "$(cat ${SSH_KEY_PATH}.pub)" zabbix_monitor
   > lsuser -name zabbix_monitor

${BLUE}2. PROBAR CONEXIÓN SSH:${NC}
   sudo -u ${ZABBIX_USER} ssh -i ${SSH_KEY_PATH} zabbix_monitor@<FLASHSYSTEM_IP> "lssystem"

${BLUE}3. IMPORTAR PLANTILLA ZABBIX:${NC}
   - Navegue a: Data Collection → Templates
   - Click en: Import
   - Seleccione: ${TEMPLATE_DIR}/zabbix_template_ibm_flashsystem_5045.yaml
   - Click en: Import

${BLUE}4. CREAR HOST EN ZABBIX:${NC}
   - Navegue a: Data Collection → Hosts
   - Click en: Create host
   - Nombre: IBM-FlashSystem-5045-<Serial>
   - Groups: Templates/IBM Storage
   - Interfaces: SNMP (IP de gestión del FlashSystem)
   - Templates: IBM FlashSystem 5045 by Go ExternalCheck
   - Macros: Configure según su entorno

${BLUE}5. VERIFICAR MONITOREO:${NC}
   - Navegue a: Monitoring → Latest Data
   - Seleccione el host creado
   - Verifique que los items muestran datos

${BLUE}6. CONFIGURAR ALERTAS:${NC}
   - Revise los triggers importados
   - Configure acciones de notificación (Email, SMS, etc.)

${YELLOW}ARCHIVOS IMPORTANTES:${NC}
   Configuración:     ${ZABBIX_CONFIG}
   Secretos:          ${SECRETS_CONFIG}
   Clave SSH:         ${SSH_KEY_PATH}
   Logs:              ${LOG_DIR}/ibm_flash_monitor.log
   Binario:           ${BIN_DIR}/ibm_flash_monitor
   Plantilla:         ${TEMPLATE_DIR}/zabbix_template_ibm_flashsystem_5045.yaml

${YELLOW}COMANDOS ÚTILES:${NC}
   Ver logs:          tail -f ${LOG_DIR}/ibm_flash_monitor.log
   Ver logs Zabbix:   tail -f /var/log/zabbix/zabbix_server.log
   Probar script:     sudo -u ${ZABBIX_USER} ${BIN_DIR}/ibm_flash_monitor <IP> system_health
   Verificar SELinux: ls -Z ${BIN_DIR}/ibm_flash_monitor

${GREEN}========================================${NC}
${GREEN}  Versión: ${PROJECT_VERSION}            ${NC}
${GREEN}  Proyecto: ${PROJECT_NAME}              ${NC}
${GREEN}========================================${NC}

EOF
}

# ================================================================================
# FUNCIÓN PRINCIPAL
# ================================================================================

main() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  ${PROJECT_NAME} - Instalador          ${NC}"
    echo -e "${GREEN}  Versión: ${PROJECT_VERSION}            ${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    
    # Validaciones previas
    check_root
    check_zabbix_user
    check_go_installed
    check_zabbix_server
    check_selinux
    
    # Instalación
    create_directories
    compile_go_binary
    create_config_files
    generate_ssh_key
    configure_selinux
    configure_zabbix_server
    copy_templates
    copy_documentation
    test_installation
    
    # Resumen final
    print_next_steps
    
    log_success "Instalación completada"
    exit 0
}

# ================================================================================
# MANEJO DE SEÑALES
# ================================================================================

cleanup() {
    log_warning "Instalación interrumpida"
    log_info "Ejecutando limpieza..."
    
    # Restaurar permisos si es necesario
    if [[ -d "${INSTALL_DIR}" ]]; then
        chown -R ${ZABBIX_USER}:${ZABBIX_GROUP} "${INSTALL_DIR}" 2>/dev/null || true
    fi
    
    exit 1
}

trap cleanup SIGINT SIGTERM

# ================================================================================
# EJECUCIÓN
# ================================================================================

# Parsear argumentos
while getopts "fhn" opt; do
    case ${opt} in
        f )
            log_info "Modo forzado activado"
            FORCE=true
            ;;
        h )
            echo "Uso: $0 [-f] [-h]"
            echo "  -f  Forzar reinstalación"
            echo "  -h  Mostrar esta ayuda"
            exit 0
            ;;
        n )
            log_info "Modo dry-run (solo simulación)"
            DRY_RUN=true
            ;;
        \? )
            echo "Opción inválida: $OPTARG"
            exit 1
            ;;
    esac
done

# Ejecutar instalación
main "$@"