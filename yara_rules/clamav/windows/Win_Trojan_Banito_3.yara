rule Win_Trojan_Banito_3
{
strings:
	$a0 = { 7374207379732a33322e646c6c2064656c207379732a33322e646c6c0000ffffffff0600000064656c2025300000ffffffff0900000073797373732e62617400000073797373732e626174000000ffffffff0100000079000000ffffffff010000005c000000ffffffff03000000793079 }

condition:
	$a0
}

        