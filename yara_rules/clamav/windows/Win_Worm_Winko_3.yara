rule Win_Worm_Winko_3
{
strings:
	$a0 = { 71712e646c6c }
	$a1 = { 64643333677364322e657865 }
	$a2 = { 25646b2e657865 }
	$a3 = { 6e5c52756e5c }
	$a4 = { 633a5c6175746f72756e2e696e66 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}

        
