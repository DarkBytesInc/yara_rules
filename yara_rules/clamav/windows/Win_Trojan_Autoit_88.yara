rule Win_Trojan_Autoit_88
{
strings:
	$a0 = { 5c43757272656e7456657273696f6e5c52756e[0-25]24646972202620226e6f646c6f67696e2e657865 }

condition:
	$a0
}

        
