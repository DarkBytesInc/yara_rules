rule Win_Trojan_Bancos_2063
{
strings:
	$a0 = { a34a6bbb2dc986213dbd063cb9d73542496fcc7f94238b41423c2cf3e87ad1f5c6da76bee6518b11f388232f2bb2fd308fe92fe0c29dbfc211e8fe0b4935874eb61795ce80dbb1528e27f8dd2829a9d0a57e05202efebe65ccc0ca55eda65a8d732a }

condition:
	$a0
}

        
