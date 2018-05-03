rule Win_Worm_Bater_1
{
strings:
	$a0 = { 6a0468ca1240006a046a0068b8124000ff35b4124000ff1548324000 }

condition:
	$a0
}

        
