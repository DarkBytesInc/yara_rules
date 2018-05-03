rule Win_Worm_Autorun_374
{
strings:
	$a0 = { 558bec538b5d08568b750c57 }
	$a1 = { 6d73746d646d2e646c6c }
	$a2 = { 253038782e746d70 }
	$a3 = { 46412e746d70 }

condition:
	$a0 and $a1 and $a2 and $a3
}

        
