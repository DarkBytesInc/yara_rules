rule Win_Trojan_Diple_7
{
strings:
	$a0 = { 558bec81eca4010000ff15????4100506a03ff15????41003b042a7445b8????40008d040255506a056a0026ff15????410056e82a00000088f4fc8d042483e8 }

condition:
	$a0
}

        
