rule Win_Trojan_Dremn_1
{
strings:
	$a0 = { 566a64ff3518104000e850000000a1181040005933f65980380074198a108bc880f2ef46 }

condition:
	$a0
}

        
