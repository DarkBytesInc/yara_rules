rule Win_Trojan_CyberWarrior_1
{
strings:
	$a0 = { cd33f681c64301565681c6f804b92e312e890cb1042e884c02b946e22e894c03b9fac32e894c052e8a }

condition:
	$a0
}

        