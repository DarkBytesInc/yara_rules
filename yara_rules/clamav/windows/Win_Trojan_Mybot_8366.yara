rule Win_Trojan_Mybot_8366
{
strings:
	$a0 = { 519c6a735867aff2d90e83978dabf1252941fc09d82e1e098ac6f1ca1045164fd07b175e1ee97ffd7f5ffeb22382bbbdecef2a81896c25d0137b7cfd7e4b689b1c626b3e953c9fb2050bfb3554a10f0414b20d35db }

condition:
	$a0
}

        
