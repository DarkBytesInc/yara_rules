rule Win_Trojan_R_74
{
strings:
	$a0 = { 7707bb120199cd26fec03c1975f7c3492068657265627920616e6e65782074686973207365 }

condition:
	$a0
}

        
