rule Win_Worm_Autorun_304
{
strings:
	$a0 = { 7368656c6c5c6472697665725c636f6d6d616e643d6472697665725c7573625c7573625f6472697665722e657865 }

condition:
	$a0
}

        