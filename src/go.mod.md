🔧 Comandos de Inicialización del Módulo

# 1. Navegar al directorio src
cd /opt/zabbix-ibm-flash/src

# 2. Inicializar módulo Go (si no existe go.mod)
go mod init zabbix-ibm-flash

# 3. Agregar dependencia de crypto para SSH
go get golang.org/x/crypto@v0.28.0

# 4. Limpiar dependencias no usadas
go mod tidy

# 5. Verificar integridad de dependencias
go mod verify

# 6. Compilar binario
go build -o ibm_flash_monitor .

# 7. Verificar binario compilado
file ibm_flash_monitor
# Expected: ELF 64-bit LSB executable, x86-64, statically linked

# 8. Verificar dependencias del binario
ldd ibm_flash_monitor
# Expected: not a dynamic executable (statically linked)

📊 Tabla de Dependencias
Dependencia
	
Versión
	
Propósito
	
Tamaño Aprox.
golang.org/x/crypto
	
v0.28.0
	
SSH ED25519, hash, cifrado
	
~2.5 MB
golang.org/x/sys
	
v0.26.0
	
Llamadas al sistema (indirecta)
	
~1.0 MB
golang.org/x/term
	
v0.25.0
	
Manejo de terminal (indirecta)
	
~0.5 MB
Total
	
-
	
-
	
~4.0 MB
🔐 Verificación de Seguridad de Dependencias

bash
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15

🏗️ Estructura Final del Módulo

1
2
3
4
5
6
7
8
9
10

✅ Checklist de Validación
Ítem
	
Comando
	
Estado Esperado
go.mod existe
	
ls -la go.mod
	
-rw-r--r--
go.sum existe
	
ls -la go.sum
	
-rw-r--r--
Dependencias descargadas
	
go mod download
	
Sin errores
Dependencias verificadas
	
go mod verify
	
all modules verified
Build exitoso
	
go build -o ibm_flash_monitor .
	
Binario creado
Binario estático
	
file ibm_flash_monitor
	
statically linked
Sin vulnerabilidades
	
govulncheck ./...
	
No vulnerabilities found
📝 Notas Importantes

    NO commits go.sum sin go.mod: Siempre van juntos
    NO editar go.sum manualmente: Usar go mod tidy
    Versionar ambos archivos: go.mod y go.sum en Git
    Excluir vendor/ en Git: A menos que necesites build offline
    Actualizar regularmente: Revisar dependencias cada 3 meses