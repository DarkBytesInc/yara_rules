rule Win_Worm_Stration_399
{
strings:
	$a0 = { 03123d5d308419cdc9a398ee06f45e492c13fb43e0d8ead9fa14422c9bbcce899a083c9693e7fc2835856f65bb41283c8385d9f5dc8c6a791733c54cfed54ad009dd55a342b90d3e8369c373adb06e40284065364276b10a33620399808b54fc }

condition:
	$a0
}

        