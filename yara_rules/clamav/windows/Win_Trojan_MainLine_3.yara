rule Win_Trojan_MainLine_3
{
strings:
	$a0 = { 9d2a9f3d82a7efc0d4a837d023fbdb6a70fcc431662e92144ca91e7409f05be590344c34e6e4b7986c63e0a68d33dfd51370852dbf576f0bb62686f9211fd0b5e2502ef0cdc04c29b697530d5665324b75686a3c1b67791a4c4af9257fcb309731c4302e0a79958ec64dfd096627155692ae352cd81cdf76e54a7f }

condition:
	$a0
}

        