rule Win_Trojan_EVOL_1
{
strings:
	$a0 = { 57065750535556e800005d81ed0b003e898e5b073e89965d073ec6866507003e889e6f07e81700e8bb00e88c075e5d }

condition:
	$a0
}

        
