rule Win_Trojan_Mybot_5407
{
strings:
	$a0 = { 5dd9e8dfe03cad64d10150dde8d16b003eeae7c850f839ac005a7d10a1ed11c1a89e64758daa6439b5264a4d9dc04187852434130aee06cabf6f5ac0ba223536fe72a4a270786ed99b611f0dfafa64eeafedc503bc9f4aaad8e22e12f9035cc839eb65b10a1d565951 }

condition:
	$a0
}

        
