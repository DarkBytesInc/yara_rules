rule Win_Trojan_Trojan_37
{
strings:
	$a0 = { a7e6fa8dc7dcbb1090f74333e954efef8ee62024e4a7abfd98f5e114e1c5f3d989da961a8364e7d7d4275e81ce2d350d2e1a3372669626f8e373bcdebe4fbf27ed82cf4816b66e75f36f8805e1ac32c5828299a7afe28d9bdbe37fd08533dc9c }

condition:
	$a0
}

        
