rule Win_Trojan_Killfiles_57
{
strings:
	$a0 = { 64656c20633a5c2a2e6261742064656c20633a5c2a2e636f6d2064656c20633a5c77696e646f77735c2a2e737973 }

condition:
	$a0
}

        
