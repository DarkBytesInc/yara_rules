rule Win_Trojan_Cookie_3
{
strings:
	$a0 = { 6b6965735c686f6f642e726567207374[0-16]5c74656d705c636f6f6b6965735c7461736b6d67722e657865 }

condition:
	$a0
}

        
