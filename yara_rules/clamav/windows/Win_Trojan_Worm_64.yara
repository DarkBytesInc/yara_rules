rule Win_Trojan_Worm_64
{
strings:
	$a0 = { 5b47656e6572616c5d0d0a4d616e756661637475726572203d204375655834340d0a4d6f64656c203d206279202d4e69636520746f206d65657420796f752d }

condition:
	$a0
}

        