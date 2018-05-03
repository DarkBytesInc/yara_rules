rule Win_Worm_Autorun_165
{
strings:
	$a0 = { 9a83e77da5683337ded5db1f4da7fe70aba4d27911b1b81e2e77479ccd8dbf76c74ecf371ad6ad1ae9495dc5fc571d18a64a3f51859c194666a002023fae00b81df098072346 }

condition:
	$a0
}

        
