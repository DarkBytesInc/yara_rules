rule Win_Worm_Stration_621
{
strings:
	$a0 = { 7ea0e0de9fff3fffce0531ce170c349eab5d173e31fdcd35e9fcda6149b22fffffffeafbc03c29d8180511e2113535d4e014597d55998074aed03d25517ffedffc1c4da0fecbb7b787ac63b6b4e091f62c693f4f70468bffff6afd5f45306522c6897fe1cdf52fcde9a8c8b57b3606ffcfff9b7b1a360ed4361241325080ed99 }

condition:
	$a0
}

        
