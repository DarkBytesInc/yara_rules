rule Win_Trojan_VGEN_39
{
strings:
	$a0 = { 9a000062005589e581ec0001bff4011e579ab00762009a0e026200bff4011e57bf7f020e5731c0509a780862009ab007 }

condition:
	$a0
}

        
