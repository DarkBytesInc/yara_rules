rule Win_Trojan_Fakealert_90
{
strings:
	$a0 = { dc5a2ef8612b1437f07afc384068e97f264ab6b7a68ca1a3fbb42dcbef5304ef187132926dbdfcf5b002d2ec00aa7b6f504fa1f0a503ab513c8e8c2d29861e770ef32758ab9d3a670df3e0a31855156c28d0def0b7fe83682a28705b3c638221ded1a1a1 }

condition:
	$a0
}

        
