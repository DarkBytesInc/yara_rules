rule Win_Trojan_Hupigon_758
{
strings:
	$a0 = { 9c1cc1733bfab3790ab746c6ee755908c998407775baec573128958fc539e1740aa14da9857237599f41fd5dec9c5e12e11e0d529951927f829bca2f317d0e165f21bcadb773a26bc62f39d52dc5 }

condition:
	$a0
}

        
