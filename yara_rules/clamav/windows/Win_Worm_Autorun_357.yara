rule Win_Worm_Autorun_357
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085f67509833da8 }
	$a1 = { 7368656c6c657865637574653d }
	$a2 = { 6d2e657865 }

condition:
	$a0 and $a1 and $a2
}

        
