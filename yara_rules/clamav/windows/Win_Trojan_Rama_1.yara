rule Win_Trojan_Rama_1
{
strings:
	$a0 = { 9a000025005589e581ec0001bf7d001e578dbe00ff165731c0509a000825009a42062500bf7d001e57b80100509a7d06 }

condition:
	$a0
}

        
