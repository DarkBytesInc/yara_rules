rule Win_Trojan_VB_338
{
strings:
	$a0 = { 7200720065006e007400560065007200730069006f006e005c00520075006e0000000e0000005200610076004d006f006e0074000000a0f5c3c7a388d011abcb00a0c90fffc00600000064003a005c0000001c00000064003a005c004100750074006f00720075006e002e0069006e00660000000000c1d8ba5318e7cf11893d00a0c9054228120000005b0041 }

condition:
	$a0
}

        