rule Win_Trojan_Bancos_718
{
strings:
	$a0 = { 96af2c23e20e6a3bdeba1a69abe3e1c6827a33fb2a43ddc6288fd3eb7cb6691402bea61216c52bc1fb0592fb871e2e4df6d846b602ca52f7255e7df4a38a7684cb04c478a94909fcd068dfabafcf2d2a8a58c2223aa64a448247e806dc2aca585be191e8ae8c5d8189a8c1c2 }

condition:
	$a0
}

        
