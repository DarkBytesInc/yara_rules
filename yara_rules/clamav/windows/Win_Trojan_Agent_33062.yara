rule Win_Trojan_Agent_33062
{
strings:
	$a0 = { ffffc642a6517496a6ba2c04fd038e076c8d785903e8d6ffffffdb24129420db57d3c601243c0fb83f06a7cd02226c20052c89b6e3fa2f71e3069c594259a0083980c1c30f1d8cffff56 }

condition:
	$a0
}

        
