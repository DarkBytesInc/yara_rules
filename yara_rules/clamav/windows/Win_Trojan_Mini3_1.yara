rule Win_Trojan_Mini3_1
{
strings:
	$a0 = { 01e9ab009c86e03c4b7503e815003cf0750980fc3175049d33c0cf86e09dea00000000505351521e0656b8014333 }

condition:
	$a0
}

        
