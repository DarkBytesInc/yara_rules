rule Win_Trojan_C_40
{
strings:
	$a0 = { 0201e800008b2e0001bcfeff81ed1d03e8d7ffe9d5fd0d0a21205741524e494e472021212054484953204953204120 }

condition:
	$a0
}

        
