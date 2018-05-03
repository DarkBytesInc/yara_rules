rule Win_Worm_Gaobot_111
{
strings:
	$a0 = { 3b7d47616f477581548f4fb1b6f07667f7d819d7c0cbe8b26f09aa880bf746613fda9184ef6d676d6744a767bd97f6dac2755a611f871fa6b148ecb72fb403b64668c4 }

condition:
	$a0
}

        
