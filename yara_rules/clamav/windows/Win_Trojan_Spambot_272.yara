rule Win_Trojan_Spambot_272
{
strings:
	$a0 = { e8182fd9eff271249964fffffffff711de24b64e7e2ccd171d5bfb6ce6a26a3027aacbe67bf4fe5ac3755217fb59fffffffa3972398c3c0a3d9e2eb0189d94916bdefd1b2fcb1e45b4ff1ffd4f5119c635614c4b9710f3ea11cd31cf06c2a4a8efff3ffecd93490b51c88717746f }

condition:
	$a0
}

        
