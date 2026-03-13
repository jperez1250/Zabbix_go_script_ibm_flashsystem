// go.mod
// IBM FlashSystem Monitor para Zabbix 7.2 ExternalCheck
// Módulo Go para monitoreo seguro de IBM Storage Virtualize V8.7
//
// Requisitos:
// - Go 1.22 o superior (compatible con Red Hat 9)
// - golang.org/x/crypto para SSH ED25519
//
// Compilación:
//   go mod tidy
//   go build -o ibm_flash_monitor .
//
// Referencias:
// - Zabbix_Documentation_7.2.en.txt: ExternalCheck specification
// - sg248561.txt: IBM Storage Virtualize V8.7 Redbook
// - svc_bkmap_cliguidebk (1).txt: CLI Command Reference

module zabbix-ibm-flash

// Versión mínima de Go requerida
// Go 1.22 recomendado para Red Hat 9 (dnf install golang)
go 1.22

// Dependencias directas del proyecto
require (
	// golang.org/x/crypto: Implementación SSH segura con soporte ED25519
	// Usado en: lib/ssh_client.go para autenticación por clave
	// Versión v0.28.0 incluye parches de seguridad críticos (2024)
	// Referencia: python-3.14-docs.txt menciona importancia de crypto actualizado
	golang.org/x/crypto v0.28.0
)

// Dependencias indirectas (auto-generadas por go mod tidy)
// Estas son dependencias de golang.org/x/crypto, no las modificamos manualmente
require (
	// golang.org/x/sys: Llamadas al sistema para operaciones de bajo nivel
	// Requerido por crypto para operaciones de archivo y permisos
	golang.org/x/sys v0.26.0 // indirect
	
	// golang.org/x/term: Manejo de terminal para SSH
	// Usado para lectura segura de credenciales (aunque nosotros no usamos passwords)
	golang.org/x/term v0.25.0 // indirect
)

// Reemplazos (replace) - NO USAR en producción a menos que sea necesario
// Ejemplo: Si necesitas usar una versión específica de una dependencia
// replace golang.org/x/crypto => github.com/golang/crypto v0.28.0

// Exclusiones (exclude) - Versiones conocidas con vulnerabilidades
// Excluir versiones antiguas de crypto con vulnerabilidades CVE
exclude (
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519
	golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d
)

// Retractions (retract) - Versiones de nuestro propio módulo con problemas
// Si publicamos el módulo, podemos retractar versiones problemáticas
// retract v0.0.1 // Versión inicial con bug de seguridad

// Notas de seguridad:
// 1. Ejecutar 'go mod verify' antes de cada release para verificar integridad
// 2. Ejecutar 'go list -m -versions golang.org/x/crypto' para ver versiones disponibles
// 3. Actualizar dependencias regularmente: 'go get -u golang.org/x/crypto'
// 4. Verificar vulnerabilidades: 'go list -m -json all | grep vuln'
// 5. Usar 'go mod vendor' para incluir dependencias en el repositorio (opcional)

// Comandos útiles para mantenimiento:
//   go mod tidy      # Limpiar dependencias no usadas
//   go mod verify    # Verificar integridad de dependencias
//   go mod download  # Descargar todas las dependencias
//   go mod graph     # Mostrar gráfico de dependencias
//   go mod why       # Explicar por qué se necesita una dependencia
//   go mod edit      # Editar go.mod programáticamente
//   go mod vendor    # Crear directorio vendor con todas las dependencias

// Para producción en entorno sin acceso a internet:
// 1. Ejecutar 'go mod vendor' en entorno con internet
// 2. Copiar directorio vendor al servidor de producción
// 3. Compilar con 'go build -mod=vendor'