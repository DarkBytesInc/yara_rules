rule Win_Trojan_Lmir_130
{
strings:
	$a0 = { 6830a70014e817f7ffff8bf083c40485f6897424107423e8a5f7ffff3bc6751a6820bf0200ff1578a000146a00ff1584a0001450ff158ca00014 }

condition:
	$a0
}

        
