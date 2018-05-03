rule Win_Worm_Stration_593
{
strings:
	$a0 = { 8b4424048bc880380074088a51014184d275f8568b74240c418a16468851ff84 }
	$a1 = { 5c0000002e65786500000000 }

condition:
	$a0 and $a1
}

        
