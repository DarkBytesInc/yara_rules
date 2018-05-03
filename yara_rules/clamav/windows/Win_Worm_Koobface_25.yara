rule Win_Worm_Koobface_25
{
strings:
	$a0 = { 6e7525733030392e62697a }
	$a1 = { 633a5c3335333435343534332e626174 }

condition:
	$a0 and $a1
}

        
