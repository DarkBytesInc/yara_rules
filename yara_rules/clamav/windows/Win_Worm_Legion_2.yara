rule Win_Worm_Legion_2
{
strings:
	$a0 = { 2e44656c65746546696c65202822433a5c57696e646f77735c2a2e2a2229 }

condition:
	$a0
}

        
