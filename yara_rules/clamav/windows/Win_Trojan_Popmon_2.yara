rule Win_Trojan_Popmon_2
{
strings:
	$a0 = { 6e7465726e6574204578706c6f726572000000005c2a2e2a0000000025735c4465616c48656c7065720000007200000073797300687474703a2f2f6164732e6465616c68656c7065722e636f6d2f6465616c68656c7065722f646174612f757365726964322e706870000000300000007573657269640000706f70737461746500000000534f4654574152455c6465616c68656c7065725c4b6579576f7264 }

condition:
	$a0
}

        