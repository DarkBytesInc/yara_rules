rule Win_Trojan_SdBot_3864
{
strings:
	$a0 = { c299c835a9d4a004b82eae93d0ab6ca71ad9d23e384d5f135b149ac5e667e6cf399028ebb63e528eed5e4f5f2a9ef97ea30b2faa535faeb11f7048c46bc41b1cc2b0130d7512cb24848175086c3337d746ea3d619f }

condition:
	$a0
}

        
