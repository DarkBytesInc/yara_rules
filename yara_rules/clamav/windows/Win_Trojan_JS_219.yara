rule Win_Trojan_JS_219
{
strings:
	$a0 = { 2863673d7268753b63673c6e625b766879695d3b63672b3d756b6b6c7029657973 }
	$a1 = { 6576616c28676e7a6b7029 }

condition:
	$a0 and $a1
}

        
