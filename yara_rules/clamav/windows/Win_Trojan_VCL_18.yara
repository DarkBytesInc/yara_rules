rule Win_Trojan_VCL_18
{
strings:
	$a0 = { b9030033c941904141eb0290908d969202cd21b8014233c94033d2ba0000cd21b440b95f014090 }

condition:
	$a0
}

        
