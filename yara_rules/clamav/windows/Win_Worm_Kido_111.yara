rule Win_Worm_Kido_111
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085f67509833d0001547c00eb2683 }
	$a1 = { 0d8244727570e77d }

condition:
	$a0 and $a1
}

        
