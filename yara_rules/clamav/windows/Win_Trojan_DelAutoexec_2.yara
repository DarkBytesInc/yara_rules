rule Win_Trojan_DelAutoexec_2
{
strings:
	$a0 = { 32e4cd1a8816c10188165a03b409ba0102cd21b43f33dbb90e00ba1202cd2103d08bf2c744fe0000b80043ba1202cd21890e2002b8014333c9cd21b8023dcd2193b43fb91800ba26028bf2cd21fc5683c60eada34f02ada35502 }

condition:
	$a0
}

        