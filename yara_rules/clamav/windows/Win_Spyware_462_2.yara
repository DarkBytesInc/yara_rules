rule Win_Spyware_462_2
{
strings:
	$a0 = { 13ea566e475949e817c478f7a08972b8da1571124949596c81f97d63737c98617b857139d028c0cba25c46935a7fa7ac31c7ab843164c2a236ceed3319eff9cb0f2e8aa23903204a152b3b61cc6572dc415cc5f584fdc8306457621a25a459f986696f13e86a6b826c11717979b0fd2a3a168403aba88a4691d69f698ff467e4 }

condition:
	$a0
}

        