rule Win_Trojan_Bifrose_152
{
strings:
	$a0 = { 33ce5e51b969caaf93161753eafcee8863d3a6749daeb16a7c70580e0d337843f7a20ecc1e19565926b22f5e6e6e0629f9750209c4aa3e6a286c1b3b6c700d52acaeae0d1158a0d8a897bc0718d87b2a }

condition:
	$a0
}

        
