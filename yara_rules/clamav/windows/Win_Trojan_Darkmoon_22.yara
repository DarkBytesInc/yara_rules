rule Win_Trojan_Darkmoon_22
{
strings:
	$a0 = { 33db6a006a006a006a006860634000e8d5eeffffa3d0564100833dd056410000744e33f6807d0800740681ce00000008 }

condition:
	$a0
}

        
