📋 Resumen de Funciones de Seguridad
Función
	
Propósito
	
Referencia Documental
NewSecureSSHClient()
	
Constructor con validaciones estrictas
	
svc_bkmap_cliguidebk (1).txt Ch.1
ExecuteCommand()
	
Ejecución con timeout y whitelist
	
Zabbix_Documentation_7.2.en.txt
ValidateCommand()
	
Validación contra whitelist de CLI
	
svc_bkmap_cliguidebk (1).txt
ValidateKeyPermissions()
	
Verifica permisos 600 en clave
	
sg248561.txt Security Ch.4
GetHostKeyCallback()
	
Verificación de host key
	
svc_bkmap_cliguidebk (1).txt
IsValidHost/Username/Port()
	
Validación de parámetros de entrada
	
Best practices
ContainsDangerousChars()
	
Prevención de inyección de comandos
	
OWASP
SanitizeParam()
	
Sanitización de parámetros
	
Best practices
FingerprintSHA256()
	
Auditoría de claves SSH
	
svc_bkmap_cliguidebk (1).txt