rule Win_Trojan_Worm_50
{
strings:
	$a0 = { 580db8978db6a13e92a42f72c5f3b4cfb21fa397e3ca6f45c6596e997b81c2c26ddaebbf15c6a3659fde3ee135aa9c716cfcc84ccb5c29814bbd5d062884cd93607cb7dcc70e3463969719c0c5f82ec726d2ab98fec6cc0a14a5aa2f366b7084 }

condition:
	$a0
}

        
