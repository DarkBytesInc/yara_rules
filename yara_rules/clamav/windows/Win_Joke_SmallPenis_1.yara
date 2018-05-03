rule Win_Joke_SmallPenis_1
{
strings:
	$a0 = { 534d414c4c2050454e495320414c4552540004ff00000005e2ffd002fd11380412000014 }

condition:
	$a0
}

        
