rule Win_Worm_Agent_35431
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085f67509833d9464011000eb2683 }
	$a1 = { c27a6e35285c522108363f30ac5b }

condition:
	$a0 and $a1
}

        
