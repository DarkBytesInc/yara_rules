rule Win_Trojan_G2_2
{
strings:
	$a0 = { 59ccb43ecc585a59ccb44fe90cff5b50532f47fd5d00654d704972452d58005b47fd205a61787820372056697275735d }

condition:
	$a0
}

        
