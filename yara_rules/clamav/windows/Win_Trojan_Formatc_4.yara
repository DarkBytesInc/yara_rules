rule Win_Trojan_Formatc_4
{
strings:
	$a0 = { 6261642e2e2e20633a5c77696e646f77735c636f6d6d616e645c666f726d61742e636f6d20633a5c715c755c6175 }

condition:
	$a0
}

        
