rule Win_Trojan_Inject_57
{
strings:
	$a0 = { 5156525557e800000000b83b264b00ffd00000000000000000000000000000 }

condition:
	$a0
}

        
