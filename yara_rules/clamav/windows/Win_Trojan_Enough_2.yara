rule Win_Trojan_Enough_2
{
strings:
	$a0 = { 2e8135110247474d75f6f902115a3c111189f91c17ba5f43dc232c4b45767981f202a5485acf3081fa55a548dc236355922c }

condition:
	$a0
}

        
