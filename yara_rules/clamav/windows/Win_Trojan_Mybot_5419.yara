rule Win_Trojan_Mybot_5419
{
strings:
	$a0 = { 0e0cd9b1f3a8ca2c3f51d88328629b58efda639d11b533922f033c7c3cbdccbb7ae3855111bf2d00799b2c935606c4f10047ad2a073b763e145d0cfd1044b2170b2a1e2da9050a6807114653e6a5ea2e663c11c8a55fdb16f97b1842e3d6bf5306d80f63081b099df9 }

condition:
	$a0
}

        