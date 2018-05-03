rule Win_Worm_Lolit_1
{
strings:
	$a0 = { a164a94300e87ce6ffff33c98b55f4a164a94300e801e7ffff84c0740fbaf46c4300a164a94300e812e8ffff }

condition:
	$a0
}

        
