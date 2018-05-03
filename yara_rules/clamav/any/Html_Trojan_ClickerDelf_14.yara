rule Html_Trojan_ClickerDelf_14
{
strings:
	$a0 = { 22e866d2f6ff33c05a595964891068f8b849008d45f4ba03000000e88c8bf6ffc3e9e684f6ffebeb5f5e5b8be55dc300ffffffff13000000687474703a2f2f7777772e326368 }

condition:
	$a0
}

        
