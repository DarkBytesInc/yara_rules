rule Win_Worm_Kido_112
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085f67509833d0001445c }
	$a1 = { 2c45396b2d453a6b2c45387a2d4534 }

condition:
	$a0 and $a1
}

        
