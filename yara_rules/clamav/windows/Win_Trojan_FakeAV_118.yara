rule Win_Trojan_FakeAV_118
{
strings:
	$a0 = { feffffba4d0400000b9550feffff4283c2550195dcfdffff1995ccfdffff83c2034a01c283fa7c751f8b85acfdffff1945c431d081c0e400000081eabf00000039957cfdffff7500ff8dccfeffff299598fdffffb8420000004829d081e8e80000001985 }

condition:
	$a0
}

        
