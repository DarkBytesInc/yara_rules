rule Win_Trojan_Banload_53
{
strings:
	$a0 = { 7c00460065006c0069007a0025003200300041006e006f002500320030004e006f0076006f0000000000ffffffff20000000633a5c77696e646f77735c73797374656d33325c64 }

condition:
	$a0
}

        