rule Xls_Trojan_Laroux_33
{
strings:
	$a0 = { 637469766543656c6c2e466f726d756c6152314331203d2022b9d9c0ccb7afbdbabfa120b0a8bfb0b5c7befac0bd2e20b8c5c5a9b7ceb9d9c0ccb7afbdbab8a620c0e2bec6b6f322 }

condition:
	$a0
}

        
