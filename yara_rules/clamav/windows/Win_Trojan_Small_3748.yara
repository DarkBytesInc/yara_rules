rule Win_Trojan_Small_3748
{
strings:
	$a0 = { 05b3a74db0caa20ec9201e22f11a75b4b11d8732c40a1f9f983c224ab04de362af3f4362afe0275af0ca7ea80d26780d0722874ac0ca1fb4b8c93482c00a1f9aafe05b5af0caaa3a1bcb896d06351f49c61e2f8ab04fdfbee2555c7ac00a1fa0afa2a40a25f07549884b9b7aaf27945206caf6 }

condition:
	$a0
}

        
