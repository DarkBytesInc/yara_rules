rule Win_Trojan_Agent_32704
{
strings:
	$a0 = { 43343f16ceba00f02e8b34d5a0a6d26ec06d694466b693f3793b77f02a5c53d98287535bd3d9f7c75e806179acd8db5fc94842b15c644b45d4f7053ed0e84d94c86a5d64 }

condition:
	$a0
}

        
