rule Win_Worm_Stration_363
{
strings:
	$a0 = { a11484c7a152373daf1a874e24e85a0477dfe7543d3f96880fbf07679a52fa2097fa25fb6bbf38373c5678c865ebd3fe817ce495f462fb89a240f971c21eb52a95b3eb9bf6e34fbf17907077d54c58fa }

condition:
	$a0
}

        
