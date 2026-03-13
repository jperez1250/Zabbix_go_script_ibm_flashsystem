📋 Resumen de Acciones Soportadas
Categoría
	
Acción
	
Parámetros
	
Output Ejemplo
LLD
	
discover_pools
	
-
	
{"data":[{"{#POOL_ID}":"0",...}]}
LLD
	
discover_safeguarded_volumes
	
-
	
{"data":[{"{#VDISK_ID}":"10",...}]}
LLD
	
discover_drives
	
-
	
{"data":[{"{#ENCLOSURE_ID}":"0","{#DRIVE_ID}":"1"}]}
Safeguarded Copy
	
safeguarded_copy_status
	
<vdisk_id>
	
"1" (healthy), "0" (problem)
Safeguarded Copy
	
safeguarded_copy_expiry_hours
	
<vdisk_id>
	
"72" (horas restantes)
Capacidad
	
pool_capacity_used_percent
	
<pool_id>
	
"78.45" (porcentaje)
Capacidad
	
pool_free_capacity_bytes
	
<pool_id>
	
"107374182400" (bytes)
Capacidad
	
pool_compression_ratio
	
<pool_id>
	
"3.50" (ratio)
Replicación
	
replication_status
	
<rel_id>
	
"1" (synchronized), "0" (broken)
Replicación
	
hyperswap_volume_status
	
<vdisk_id>
	
"1" (both online), "0" (both down)
Hardware
	
drive_status
	
<enc_id>, <drive_id>
	
"1" (online), "0" (failed)
Hardware
	
enclosure_battery_status
	
<enc_id>, <bat_id>
	
"1" (online), "0" (failed)
Sistema
	
system_health
	
-
	
"1" (online), "0" (offline)
Sistema
	
critical_events_count
	
-
	
"0" (sin eventos críticos)
Volumen
	
volume_status
	
<vdisk_id>
	
"1" (online), "0" (offline)