rule Win_Trojan_Maran_8
{
strings:
	$a0 = { 6a01e867f9ffffa1ac504000c60001b8fc424000a3f8674000c705fc674000b040400068f8674000e8b9f9ffff33c05a5959648910 }

condition:
	$a0
}

        
