rule Win_Trojan_IVP_24
{
strings:
	$a0 = { 8d9e????????012e8ab6????2e8a2732e62e882743e2f5c3 }

condition:
	$a0
}

        
