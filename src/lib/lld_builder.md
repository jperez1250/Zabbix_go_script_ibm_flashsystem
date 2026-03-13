📋 Resumen de Funciones LLD
Función
	
Propósito
	
Comando CLI
	
Output
	
Referencia
BuildPoolLLD()
	
LLD para pools
	
lsmdiskgrp
	
JSON {"data":[...]}
	
Zabbix_Documentation_7.2 p.1520
BuildVolumeLLD()
	
LLD para volúmenes
	
lsvdisk
	
JSON {"data":[...]}
	
Zabbix_Documentation_7.2 p.1520
BuildDriveLLD()
	
LLD para drives
	
lsdrive
	
JSON {"data":[...]}
	
svc_bkmap_cliguidebk
BuildSafeguardedVolumeLLD()
	
LLD Safeguarded Copy
	
lsvdiskcopy
	
JSON {"data":[...]}
	
sg248561.txt §6.3
BuildReplicationLLD()
	
LLD replicación
	
lsrcrelationship
	
JSON {"data":[...]}
	
sg248543.txt Cap.7
BuildEnclosureLLD()
	
LLD enclosures
	
lsenclosure
	
JSON {"data":[...]}
	
svc_bkmap_cliguidebk
BuildArrayLLD()
	
LLD arrays
	
lsarray
	
JSON {"data":[...]}
	
svc_bkmap_cliguidebk
MarshalLLDResult()
	
Serializar JSON compacto
	
-
	
String JSON
	
Zabbix_Documentation_7.2
ValidateLLDJSON()
	
Validar JSON LLD
	
-
	
bool/error
	
Zabbix_Documentation_7.2
FilterLLDByStatus()
	
Filtrar por estado
	
-
	
[]LLDItem
	
Custom
GetLLDMacros()
	
Extraer macros
	
-
	
[]string
	
Zabbix_Documentation_7.2
