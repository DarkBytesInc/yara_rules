rule Win_Dropper_Small_60
{
strings:
	$a0 = { 542e455845005550444154452e455845004e555047524144452e455845004d435550444154452e4558450000687474703a2f2f6d697261636c652e76 }

condition:
	$a0
}

        