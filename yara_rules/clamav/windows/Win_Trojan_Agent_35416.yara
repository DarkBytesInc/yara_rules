rule Win_Trojan_Agent_35416
{
strings:
	$a0 = { 558bec6aff687030400068f02d400064a100000000506489250000000083ec685356 }

condition:
	$a0
}

        
