rule Win_Trojan_B_73
{
strings:
	$a0 = { cd1361727980fe00757483f901756f50535657e8600072562681bffe0155aa7549e8a10026 }

condition:
	$a0
}

        
