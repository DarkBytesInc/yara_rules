rule Win_Trojan_Autorun_345
{
strings:
	$a0 = { 5b6175746f72756e5d0d0a5368656c6c657865637574653d73797374656d63686b2e6578650d0a }

condition:
	$a0
}

        
