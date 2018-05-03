rule Html_Trojan_ClickerDelf_9
{
strings:
	$a0 = { 61160cd3afcdd0118a3e00c04fc9e26effffffff26000000687474703a2f2f667265652e6863776f }

condition:
	$a0
}

        
