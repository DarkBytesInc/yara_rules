rule Win_Trojan_Bancos_1015
{
strings:
	$a0 = { 96f4ff7025d0c02d3dbb32b66701ac7b179bf71ba1f011d5a5fd8f9af2d81b2347deeeb9fff63018d0edec8eb7f0b7ea6b9a479173f3d3a1bfd004549be943046fd88913362e22f25d2bf65015d9dead292214e348 }

condition:
	$a0
}

        
