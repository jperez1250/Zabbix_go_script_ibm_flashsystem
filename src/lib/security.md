📋 Resumen de Funciones de Seguridad
Categoría
	
Función
	
Propósito
	
Referencia Documental
Inicialización
	
InitSecurity()
	
Inicializa contexto y logging
	
sg248561.txt Cap.4
Inicialización
	
GetSecurityContext()
	
Obtiene contexto de seguridad
	
Zabbix_Documentation_7.2
Logging
	
LogInfo/Warning/Error/Critical()
	
Logs por nivel de severidad
	
sg248561.txt §4.2.2
Logging
	
LogEntry()
	
Crea entrada estructurada de log
	
python-3.14-docs.txt
Logging
	
rotateLogIfNeeded()
	
Rotación automática de logs
	
Best practices
Validación
	
ValidateRunningUser()
	
Valida usuario de ejecución
	
sg248561.txt Cap.4
Validación
	
ValidateFilePermissions()
	
Valida permisos de archivos
	
svc_bkmap_cliguidebk
Validación
	
ValidateNotRoot()
	
Previene ejecución como root
	
Security best practices
Secretos
	
LoadSecretFromFile()
	
Carga segura de secretos
	
sg248561.txt Credentials
Secretos
	
SecureErase()
	
Borra datos de memoria
	
python-3.14-docs.txt
Auditoría
	
AuditCommandExecution()
	
Auditoría de comandos
	
sg248561.txt §4.2.2
Auditoría
	
AuditSecurityEvent()
	
Eventos de seguridad
	
sg248561.txt §4.2.2
Auditoría
	
AuditFileAccess()
	
Acceso a archivos sensibles
	
sg248561.txt §4.2.2
Utilidades
	
calculateFileChecksum()
	
Checksum SHA256 para integridad
	
python-3.14-docs.txt
Utilidades
	
GetLogStats()
	
Estadísticas de logging
	
Zabbix_Documentation_7.2
Cleanup
	
Cleanup()
	
Limpieza segura al finalizar
	
Best practices