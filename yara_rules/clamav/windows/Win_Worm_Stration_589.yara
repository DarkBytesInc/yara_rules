rule Win_Worm_Stration_589
{
strings:
	$a0 = { 464645492a1b3c5b4a7c485f5fffcfffbb3a3790a1b6b2a7b695babfb692d322071c0110331c1910ffcfffb7751bead7c6dbffddc0cccadcdcaf597b6a4d676d6a7b73fbffefff5a776c7b7d6a716c67 }

condition:
	$a0
}

        
