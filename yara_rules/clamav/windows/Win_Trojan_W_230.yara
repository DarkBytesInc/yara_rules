rule Win_Trojan_W_230
{
strings:
	$a0 = { 4f766572666c6f770061727475703d2200000000ffcc310000e39fb7d69e86d41189d800001cd9d64ae49fb7d69e86d4 }

condition:
	$a0
}

        
