rule Win_Trojan_Xtreme_672
{
strings:
	$a0 = { e95d81ffffebe05f5e5be8ff82ffff0000006f00700065006e000000000058005400520045004d004500550050004400 }

condition:
	$a0
}

        
