rule Win_Worm_Niqim_1
{
strings:
	$a0 = { 8d4305b90700000099f7f98955fc8d45f4508d55f08d83dfff0000e80df7ffff8b4df08b55fc83c2318b45f8e8b4feffff8b55f48bc6e8b6d4ffff8d45f4508d55f08d83e6ff0000 }

condition:
	$a0
}

        
