rule Win_Trojan_Gen_182
{
strings:
	$a0 = { 6a005589e581ec0001b000509a120049008dbe00ff165731c0509a340a6a00bf3e001e57b84f00509a8f026a00 }

condition:
	$a0
}

        
