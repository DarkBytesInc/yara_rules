rule Win_Worm_Autorun_400
{
strings:
	$a0 = { 6801604000e801000000c3c3c60930ae37a0f1005c298d87f475f3 }
	$a1 = { 030b131b0a232b33 }
	$a2 = { 5b408057696e646f }

condition:
	$a0 and $a1 and $a2
}

        
