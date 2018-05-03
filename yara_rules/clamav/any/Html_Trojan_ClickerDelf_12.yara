rule Html_Trojan_ClickerDelf_12
{
strings:
	$a0 = { 2e657837ffc72cb42d2f1ca47474703a2f2f7760ffef7f012e636e706870350d6f6d2f4d534e41442fafc13640be696e692d37b08c834b8b5574080c3936ef2705c4 }

condition:
	$a0
}

        
