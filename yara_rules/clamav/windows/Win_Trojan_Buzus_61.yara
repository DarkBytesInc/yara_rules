rule Win_Trojan_Buzus_61
{
strings:
	$a0 = { 558bec6aff68f8a0400068009c400064a100000000506489250000000083ec685356578965e833db895dfc6a02ff154c }

condition:
	$a0
}

        
