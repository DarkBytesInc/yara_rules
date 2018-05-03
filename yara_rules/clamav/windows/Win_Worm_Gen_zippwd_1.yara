rule Win_Worm_Gen_zippwd_1
{
strings:
	$a0 = { 504b03040a0001000800 }
	$a1 = { 504b010214000a0001000800 }
	$a2 = { 504b05060000000003000300 }

condition:
	$a0 and $a1 and $a2
}

        
