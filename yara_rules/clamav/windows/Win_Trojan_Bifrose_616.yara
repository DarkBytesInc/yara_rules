rule Win_Trojan_Bifrose_616
{
strings:
	$a0 = { afa1773bb8fd0850a56c3200cb498e989260aca996f8cd2c9eb6c6f20d7f4541ae9b13596fe3b1fdfbff24826f3c7210f988f3413ad62c41fcfad01d53f0da6b31e4b97593f8999bab8b2085c093087152134876297264b023e676d2e2f27745098ecbddd7a5eaeecb3e0bcedbf304304abcb0860c170f01d69c18ec6fb705cb9167ecf7eff543c78d3832022cc50616a8f0460dd2a0 }

condition:
	$a0
}

        