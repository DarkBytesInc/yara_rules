rule Win_Proxy_Lager_50
{
strings:
	$a0 = { be21605f2b8bc5a782cf729e57310189bb8481506f5cfa2740335a90cf7ad90ec3733d28d186de8c53b47b52b8b942387dc08ef33e1f40c8b7bfd41180eded69838a97a4c8da }

condition:
	$a0
}

        
