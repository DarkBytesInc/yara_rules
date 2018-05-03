rule Win_Worm_Sever_2
{
strings:
	$a0 = { ec4e33322f517569636b487417fd2b9b2d8c17477269736f66184ed9adbc8e47363376500c85edca2e09616c6754086a19cada76654f }

condition:
	$a0
}

        
