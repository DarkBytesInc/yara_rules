rule Win_Trojan_Mybot_5890
{
strings:
	$a0 = { e315715fcf597a0cb64d63eccbbc6d8731e8d3aeaa1292754d6172590a014ac91b66415231b7abcbe25d467264ea3fbd48f6f8f6c0714c78afcc6e06bd515b762cf2ca0756eaa9af8e537354cfd65d987e0ddaad60b839e7ffc6b2afd35a7b62717ccb5082b5dc542654daf3ce12 }

condition:
	$a0
}

        
