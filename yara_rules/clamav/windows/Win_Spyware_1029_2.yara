rule Win_Spyware_1029_2
{
strings:
	$a0 = { 73796d61e063156f6c4423b49e618c6d6361b09525ec66656513471db20f9081326176 }

condition:
	$a0
}

        
