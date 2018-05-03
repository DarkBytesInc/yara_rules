rule Win_Worm_N_2
{
strings:
	$a0 = { 48dc6512ed4d3d6d0bade96eb36a2583ab48ac7b92caed4c75636b6c466b211231e00ce77cb0edb8dc79cad42a75149c02a864f498f59cf7a80fd93218ce7760 }

condition:
	$a0
}

        
