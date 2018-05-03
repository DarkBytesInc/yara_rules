rule Win_Worm_Deborm_9
{
strings:
	$a0 = { 81eca002000083c9ff33c08d94249c0100005657bf0c724000f2ae }

condition:
	$a0
}

        
