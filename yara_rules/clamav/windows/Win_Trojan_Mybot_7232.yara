rule Win_Trojan_Mybot_7232
{
strings:
	$a0 = { d361dd8f8342893976fd9eb357387b57ae39b8a22a5233121546a1b3939b97a646aeadd8628241958db355063ffb8bfce2a7a3c90bd0a173f6eaaf371cb9a92b11560f6aec6a7228cc001ddc8db1 }

condition:
	$a0
}

        
