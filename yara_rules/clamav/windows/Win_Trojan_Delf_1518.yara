rule Win_Trojan_Delf_1518
{
strings:
	$a0 = { 33c089465c5e5bc35356578bd866837b420074088bd38b4344ff53408b43308b70084e85f67c154633ff8b43 }
	$a1 = { 65697a68752e5458540000ffffffff }

condition:
	$a0 and $a1
}

        
