rule Win_Trojan_Worm_2
{
strings:
	$a0 = { 7b191cf96c4705111e9d88fe077a426a209aaed80bbd73e9a711414d2f504d9a0d074d651d6697150f000f00205402e1c217a8c900eeb29f7f85fcc50f2ac37fc30dd0558bc371eb0c55b8fcae408d00 }

condition:
	$a0
}

        
