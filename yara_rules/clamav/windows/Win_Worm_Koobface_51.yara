rule Win_Worm_Koobface_51
{
strings:
	$a0 = { 633a5c77656273657276782e626174 }
	$a1 = { 6e657473[0-26]257320454e41424c45005c }

condition:
	$a0 and $a1
}

        
