rule Win_Trojan_Fraudload_12
{
strings:
	$a0 = { 0fdefffe51deff78c3dd05cafeff98a3b8defffe4763d5fefefffffefeffff7bb01dded4feffff18d2ddf62c86defffef72dfd4d03de4dfe97de0b094797bb50af8a1ce76948fd96fe1b1dd80c4d4bfe85c9f72c8af2d7cbfe01442727cb7756746682ce }

condition:
	$a0
}

        
