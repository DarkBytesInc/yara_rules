rule Win_Trojan_Mybot_7040
{
strings:
	$a0 = { 771907d1b5b0a9e1a5a8737dcb13c363b48b73a4dcae384e0f119d63c44661b9c2afc68b7916b0b61283b92b6bd1f12e3298e614e4f7331cf2d272c61c1e68dde24b55275760b76690c807f6ae4a203197f56188b6f2d6d68d4ff4f33da9b949d4c498fff441627101460363bd06e7ef2f83e9cf159d7f64bab1bae8f92e0564f33009d9e1a49de76fac7c0395667b636e8b5b2a7f1f }

condition:
	$a0
}

        