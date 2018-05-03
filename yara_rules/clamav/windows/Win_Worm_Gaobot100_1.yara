rule Win_Worm_Gaobot100_1
{
strings:
	$a0 = { 10fc9c4d075347202573373a3063726577f479306f751d210d0aa2841824476f3920689d6d65586e }

condition:
	$a0
}

        
