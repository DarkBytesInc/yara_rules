rule Win_Trojan_Delsys_8
{
strings:
	$a0 = { 64656c20633a5c77696e646f77735c6578706c6f7265722e657865203e6e756c2064656c[0-15]5c77696e2e696e69 }

condition:
	$a0
}

        
