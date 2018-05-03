rule Win_Worm_Torvil_1
{
strings:
	$a0 = { 7bec47166e8ef137fc22ef0355c45d6d4b69a1d0bc0a84a4b20ea8be2ff030438e4fe13e50ae19d43fadd36898c25b6ef1d324f6e57c2d08fb4ddfb679439120 }

condition:
	$a0
}

        
