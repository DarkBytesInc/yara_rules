rule Win_Trojan_Rbot_57
{
strings:
	$a0 = { 558bec6aff6890304000681022400064a100000000506489250000000083ec6853565789 }

condition:
	$a0
}

        
