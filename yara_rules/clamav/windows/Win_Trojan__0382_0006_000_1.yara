rule Win_Trojan__0382_0006_000_1
{
strings:
	$a0 = { f03d00f07502eb338bd5b97002b440cd21b8004233c933d2cd2181c77002c60503c6450101 }

condition:
	$a0
}

        
