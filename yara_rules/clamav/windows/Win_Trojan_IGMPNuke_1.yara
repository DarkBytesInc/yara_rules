rule Win_Trojan_IGMPNuke_1
{
strings:
	$a0 = { dabdc059d785f030ed9b76751bb9bfc093edf2f10d751ec8240f751f496e6105fe75eceb398ac1045a1f10e91b9b7b200621ea318d4c130303abb9ed76c607d0803fccf7b8c788c2aced60075ed288f6d0ec87ffd77306f0be9bd97dfa9bdbe2d98e68adbfe14ed9ee9d84868a3e }

condition:
	$a0
}

        
