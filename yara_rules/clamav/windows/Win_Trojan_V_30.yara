rule Win_Trojan_V_30
{
strings:
	$a0 = { f0015051e4610c03e661b0b6e643b8c507e6428ac4e642b900009393e2fce46124fce6615958c35a1b7b0b22057000 }

condition:
	$a0
}

        
