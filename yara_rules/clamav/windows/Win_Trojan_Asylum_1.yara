rule Win_Trojan_Asylum_1
{
strings:
	$a0 = { ffe8f641fbff0000ffffffff1b0000004173796c756d2053657276657220436f6e6669672076302e312e32000000000032 }

condition:
	$a0
}

        
