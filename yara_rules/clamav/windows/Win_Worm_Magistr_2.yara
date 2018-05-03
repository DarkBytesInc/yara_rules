rule Win_Worm_Magistr_2
{
strings:
	$a0 = { 60e8060000008b642408eb0c2bc964ff31648921fe01ebe8be00000000648f065ee800000000 }

condition:
	$a0
}

        
