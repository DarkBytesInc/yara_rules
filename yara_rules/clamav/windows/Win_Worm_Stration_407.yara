rule Win_Worm_Stration_407
{
strings:
	$a0 = { ac8e86ecd265ffb78ae1896939673fb3bcca70c6049fd4abb209f5745f01837ac3d4b89fb5f5e4de0ab626c3c5085e91f96b28b646207e2979776458daaef9cd67213f4e736475ee64d31047eb416a2270cd7afb0bfac0389f3e4a8fd514091c }

condition:
	$a0
}

        