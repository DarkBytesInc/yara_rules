rule Win_Trojan_Small_147
{
strings:
	$a0 = { 656c6c6f202d20436f7079726967687420532026205320496e7465726e6174696f6e616c2c20313939300a0d }

condition:
	$a0
}

        