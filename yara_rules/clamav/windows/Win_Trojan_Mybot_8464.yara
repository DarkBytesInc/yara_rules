rule Win_Trojan_Mybot_8464
{
strings:
	$a0 = { 25e8ffd409db308d208a987341244c4b5761d6b295f7d6e05299b9c9e81306f72ef1dff6d198fab0a807cc403b434134f71556feec183ac97a126d194e3ba69f66cdf785d6daa88af726f8ec5b4aa04e4af00e684a }

condition:
	$a0
}

        
