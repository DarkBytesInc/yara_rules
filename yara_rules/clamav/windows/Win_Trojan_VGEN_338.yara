rule Win_Trojan_VGEN_338
{
strings:
	$a0 = { 9a00001e015589e5b802009acd021e0183ec02bf02001e57bf52011e57b8ff00509a120a1e01a0520130e48946feb801 }

condition:
	$a0
}

        
