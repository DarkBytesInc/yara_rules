rule Win_Spyware_Banker_3161
{
strings:
	$a0 = { b4ba04ca57702e6541626be6c411e3a8c23769f98410021038781489cedd951c6afbb9126f24bf66e3ad8e1c65af5861ed98a256968f9ffe6208431d6efef8e23948a9d854431b4a2d958709d792b45df44c2bdb627c438d2a7b3f9ad840a8f9f060012dc4cfe09e793d96b04211a023efa013daae7a60b02acffc8b83f9cf9ce506d67fe423bcdb7f13167b }

condition:
	$a0
}

        