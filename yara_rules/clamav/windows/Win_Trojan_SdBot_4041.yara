rule Win_Trojan_SdBot_4041
{
strings:
	$a0 = { bd9235574da60096bcb4ded24a4de75a4550eef78b8e77d9c163bee5d41b1670e349ba999aacd2c97f14199df6fe4b83c6cd1dc2b694190744fbb8692b453fe90388afae04b8e8e5c0d24ac59593b1e56b171959d4aa }

condition:
	$a0
}

        
