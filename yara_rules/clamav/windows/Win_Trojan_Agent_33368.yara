rule Win_Trojan_Agent_33368
{
strings:
	$a0 = { 47fcbcd0ba2f2b6b9b84ada0a584c76ae70000207eb03788f15f5a38c8e7cd6e4db744e23951dfdaa276507b6e753354edfdc92a465c70893f1c83b737b843e9bb585de016e0beea2729d290c6c74892c559613f4abdd572ea0ca9d7 }

condition:
	$a0
}

        
