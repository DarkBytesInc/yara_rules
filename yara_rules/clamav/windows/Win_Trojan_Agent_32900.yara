rule Win_Trojan_Agent_32900
{
strings:
	$a0 = { d0b9be13d3aa7813f9b71be895091d6986a71e02ae3be63c98eea63ff58a095a835c5e6a330d2eec651ada3c27b98aca983f5892058a246dfff2ad5d430ca1459c8f72da5e0ca153306657d8a90d28097086fe8a04 }

condition:
	$a0
}

        
