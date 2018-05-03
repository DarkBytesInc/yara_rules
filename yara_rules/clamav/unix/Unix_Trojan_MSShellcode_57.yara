rule Unix_Trojan_MSShellcode_57
{
strings:
	$a0 = { 6e632031302e372e37372e3138362034343434202d65202f62696e2f736820 }

condition:
	$a0
}

        
