rule Osx_Trojan_Imuler_4
{
strings:
	$a0 = { 706f746c69676874[0-32]6c61756e63682d[0-20]2f73680a6f }

condition:
	$a0
}

        
