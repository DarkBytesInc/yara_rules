rule Win_Trojan_Trivial_473
{
strings:
	$a0 = { ba270131c9cd21721bba9e00b8023dcd218bd8b440ba0001b12dcd21b43ecd21b44febdcc32a }

condition:
	$a0
}

        
