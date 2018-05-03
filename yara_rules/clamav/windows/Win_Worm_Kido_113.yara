rule Win_Worm_Kido_113
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085f67509833d6864011000eb26 }
	$a1 = { 5c6eb055d3dc56584d }

condition:
	$a0 and $a1
}

        
