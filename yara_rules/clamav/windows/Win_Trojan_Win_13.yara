rule Win_Trojan_Win_13
{
strings:
	$a0 = { 40f1013200524154208e821c4de5654e5a2beb46a0041b4803782d76987ba803e3f82711d40b1de869370385d31c5a08 }

condition:
	$a0
}

        
