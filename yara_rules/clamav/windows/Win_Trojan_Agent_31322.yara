rule Win_Trojan_Agent_31322
{
strings:
	$a0 = { 5cc77875666a6e697c5a69dcfdc2eeff586b7c77616e77786b6112617a345b776e7357f6d7dab624792352d2062f48776adb001b61ed7874 }

condition:
	$a0
}

        
