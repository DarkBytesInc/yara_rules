rule Win_Spyware_Banker_1228
{
strings:
	$a0 = { e3e3d579be71e058de6a3a58149acf3d2593671ad93837f51e4940602f2e3c3fcbee26b4173ecfae596d23c3a10ee0bca199aae6b95a3dcafdf7746db89f22519a27f5359686cc15c1bcbc71b2e352dbcf06de961e33159dca7f }

condition:
	$a0
}

        
