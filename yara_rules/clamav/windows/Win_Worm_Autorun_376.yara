rule Win_Worm_Autorun_376
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085 }
	$a1 = { 25735c312e747874 }
	$a2 = { 5c77696e2e636f6d }
	$a3 = { 46412e746d70 }

condition:
	$a0 and $a1 and $a2 and $a3
}

        
