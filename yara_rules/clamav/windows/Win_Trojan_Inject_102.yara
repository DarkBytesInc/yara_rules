rule Win_Trojan_Inject_102
{
strings:
	$a0 = { 6858134000e8f0ffffff000000000000300000004000000000000000ab4d0cc4e38a4b4eb7bbbfa25e96a6130000000000000100000000000000000071474b4d4565476c56524600000000000000000007000000b8014700070000007401470007000000280147000600000044a543000700000094a4430001000300383b4000 }

condition:
	$a0
}

        