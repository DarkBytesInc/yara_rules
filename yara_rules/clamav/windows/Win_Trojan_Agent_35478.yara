rule Win_Trojan_Agent_35478
{
strings:
	$a0 = { 22433a5c57494e444f57535c73797374656d5c[0-15]2e657865222069[0-4]64656c202530 }

condition:
	$a0
}

        
