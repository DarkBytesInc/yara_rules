rule Win_Worm_Koobface_28
{
strings:
	$a0 = { 686172546f4f6500633a5c34333435343335342e626174 }

condition:
	$a0
}

        
