rule Win_Worm_LoveLetter_19
{
strings:
	$a0 = { 5b6175746f72756e5d0d0a6f70656e3d433a5c57494e444f57535c4f4f4248434447432e564253 }

condition:
	$a0
}

        
