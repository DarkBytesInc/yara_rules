rule Win_Trojan_FakeAV_116
{
strings:
	$a0 = { d1ff8dbcfdffffff8d7cffffff31d20995c0fdffff09ca0b9574fdffff21d181e9ec000000118d00fdffffff8510feffff4921d1118db8feffffc9c3909090909090558bec81ec0803000029c02385c0feffff81c000170000318560fdffff83f8007411 }

condition:
	$a0
}

        
