rule Win_Worm_Petik_13
{
strings:
	$a0 = { 6d656c2e6174746163686d656e74732e6164642822633a5c22267662736e29 }

condition:
	$a0
}

        
