rule Win_Trojan_AntiTrace_1
{
strings:
	$a0 = { ecc7460200015d5053515256571e06e800005b81eb1500e836012ec7875101f0002e019f51012ec7874201f000 }

condition:
	$a0
}

        
