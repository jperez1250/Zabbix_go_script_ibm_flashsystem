📋 Resumen de Funciones de Métricas
Categoría
	
Función
	
Comando CLI
	
Output
	
Referencia
Safeguarded Copy
	
SafeguardedCopyStatus()
	
lsvdiskcopy
	
"1"/"0"/"-1"
	
sg248561.txt §6.3
Safeguarded Copy
	
SafeguardedCopyExpiryHours()
	
lsvdiskcopy
	
Horas restantes
	
sg248561.txt §6.3
Capacidad
	
PoolCapacityUsedPercent()
	
lsmdiskgrp
	
"78.45" (%)
	
sg248561.txt Cap.3
Capacidad
	
PoolFreeCapacityBytes()
	
lsmdiskgrp
	
Bytes libres
	
sg248561.txt Cap.3
Capacidad
	
PoolCompressionRatio()
	
lsmdiskgrp
	
"3.50" (ratio)
	
sg248543.txt
Volúmenes
	
VolumeStatus()
	
lsvdisk
	
"1"/"0"
	
svc_bkmap_cliguidebk
Volúmenes
	
VolumeCapacityBytes()
	
lsvdisk
	
Bytes
	
svc_bkmap_cliguidebk
Replicación
	
ReplicationStatus()
	
lsrcrelationship
	
"1"/"0"
	
sg248543.txt Cap.7
Replicación
	
HyperSwapVolumeStatus()
	
lsvdisk
	
"1"/"0"/"2"
	
sg248543.txt Cap.7
Hardware
	
DriveStatus()
	
lsdrive
	
"1"/"0"
	
svc_bkmap_cliguidebk
Hardware
	
EnclosureBatteryStatus()
	
lsenclosurebattery
	
"1"/"0"
	
sg248543.txt
Hardware
	
EnclosurePSUStatus()
	
lsenclosurepsu
	
"1"/"0"
	
svc_bkmap_cliguidebk
Sistema
	
SystemHealthStatus()
	
lssystem
	
"1"/"0"
	
svc_bkmap_cliguidebk
Sistema
	
CriticalEventsCount()
	
lseventlog
	
Número
	
sg248561.txt Cap.4
LLD
	
DiscoverPools()
	
lsmdiskgrp
	
JSON
	
Zabbix_Documentation_7.2
LLD
	
DiscoverSafeguardedVolumes()
	
lsvdiskcopy
	
JSON
	
Zabbix_Documentation_7.2
LLD
	
DiscoverDrives()
	
lsdrive
	
JSON
	
Zabbix_Documentation_7.2
LLD
	
DiscoverVolumes()
	
lsvdisk
	
JSON
	
Zabbix_Documentation_7.2
LLD
	
DiscoverReplications()
	
lsrcrelationship
	
JSON
	
Zabbix_Docum