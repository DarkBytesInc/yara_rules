rule Win_Trojan_VCL_15
{
strings:
	$a0 = { b9030033c94190414190908d968602cd21b8014233c94033d2ba0000cd21b440b953014090 }

condition:
	$a0
}

        
