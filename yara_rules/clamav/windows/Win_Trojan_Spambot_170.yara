rule Win_Trojan_Spambot_170
{
strings:
	$a0 = { 211572837e19fcffffff581f8ee8cb73a1d834023bda7fe537b2ccefbb44d5e3a566ecde944888a2ffff3f698ff1af9bca276c3c6c339d1bc13005f8f26a49fdffffff60e292f720192ac6a2cc99611ea8f1f468add10aafccaf33385ff1d0a065ffffff7ff19fce209d50d86598 }

condition:
	$a0
}

        
