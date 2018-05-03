rule Win_Worm_Astro_1
{
strings:
	$a0 = { 2e6174746163686d656e74732e6164642822617374726f6c696e6b2e6a732229 }

condition:
	$a0
}

        
