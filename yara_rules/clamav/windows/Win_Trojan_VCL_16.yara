rule Win_Trojan_VCL_16
{
strings:
	$a0 = { b9030033c941904141eb0290908d968802cd21b8014233c94033d2ba0000cd21b440b955014090 }

condition:
	$a0
}

        
