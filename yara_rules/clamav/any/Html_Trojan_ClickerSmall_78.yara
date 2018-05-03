rule Html_Trojan_ClickerSmall_78
{
strings:
	$a0 = { 73ebb801000000d1e375078b1e83eefcd1d311c0d1e373ef75098b1e83eefcd1d373e431c983e803720dc1e0088a0646 }

condition:
	$a0
}

        
