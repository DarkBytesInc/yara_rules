rule Win_Trojan_Psyme_66
{
strings:
	$a0 = { 243d22253634642533642532327d }
	$a1 = { 2533627d253362223b6576616c28756e65736361706528242929 }

condition:
	$a0 and $a1
}

        
