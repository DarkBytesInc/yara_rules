rule Unix_Trojan_MSShellcode_26
{
strings:
	$a0 = { 6e63202d36202d6c702034343434202d65202f62696e2f7368 }

condition:
	$a0
}

        
