rule Win_Trojan_Lineage_340
{
strings:
	$a0 = { 8a63ce4e952bf954d577f0edd73d08b4d8c52742653bc7c43d772ba75132655cba53f92bcafeae943b38559606cc597db3e53d24da7e94cbaa19ac70c05647116f075d4236bf513270de02e22d7ff5131ee9124c4ab70606acd7c3c5905f347ac083ae17ab5ba446f7376caff1587d8d1d811f5dea20780a65a54cf2f10df9348a9621daa44a1b7bd8bee60dcad5f3329ccc9f7802d8 }

condition:
	$a0
}

        