rule Win_Spyware_11296_1
{
strings:
	$a0 = { 5381c400ffffff8bdc688033400053e8a0ecffff68185e400053e88decffff688833400053e882ecffff6808594000b9983340008bd3b800000080e87cf2ffff }

condition:
	$a0
}

        
