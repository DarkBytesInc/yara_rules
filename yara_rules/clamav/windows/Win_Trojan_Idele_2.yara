rule Win_Trojan_Idele_2
{
strings:
	$a0 = { 6830750000e80c0000006a00e800000000e805000000e80000000060b8271040 }
	$a1 = { 6369626c652a2e657865 }

condition:
	$a0 and $a1
}

        
