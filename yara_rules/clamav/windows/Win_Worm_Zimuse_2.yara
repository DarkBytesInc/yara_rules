rule Win_Worm_Zimuse_2
{
strings:
	$a0 = { 5c424f4f542e494e49 }
	$a1 = { 433a5c4e544445544543542e434f4d }
	$a2 = { 433a5c424f4f54534543542e42414b }
	$a3 = { 52656c656173652f6d7365752e737973 }

condition:
	$a0 and $a1 and $a2 and $a3
}

        
