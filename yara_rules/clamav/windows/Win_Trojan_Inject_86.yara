rule Win_Trojan_Inject_86
{
strings:
	$a0 = { 558bec6aff68f818400068e027400064a100000000506489250000000083ec685356578965e833 }

condition:
	$a0
}

        
