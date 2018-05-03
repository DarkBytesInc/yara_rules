rule Win_Worm_Lorie_1
{
strings:
	$a0 = { 2be33abca4da02a78520059506c64c1de3763502fe34bf7736d6b99cae3ba771cccbc883355402a7fe1fc0e0f0c12ff772930638005abbdfa39fbb8745bcedee87d6863636ef380822c6ba5321a542fe }

condition:
	$a0
}

        
