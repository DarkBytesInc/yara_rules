rule Win_Trojan_Gen_176
{
strings:
	$a0 = { 82005589e5b800039acd02820081ec00039a760c82008dbe00ff1657b80100509a5b0882008dbe00fe1657bf61 }

condition:
	$a0
}

        
