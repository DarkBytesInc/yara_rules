rule Win_Trojan_Destrukor_2
{
strings:
	$a0 = { 5030e4edfb3628de1afa0569433cfc688978245f1b155ebd116024e733d2340c902707ecbb656696e7a91afcf811f45090bb802447e63f633af07b0505d7d4b90ac002a7025deb16a3e1ba256d91ccdb }

condition:
	$a0
}

        
