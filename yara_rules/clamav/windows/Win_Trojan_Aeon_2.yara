rule Win_Trojan_Aeon_2
{
strings:
	$a0 = { 5c77696e646f77735c63757272656e7476657273696f6e5c72756e5c61656f6e22222c20616537 }

condition:
	$a0
}

        
