rule Win_Joke_Schmilz_1
{
strings:
	$a0 = { b960264200ba8c0b4200a124264200e867f1ffffa124264200e8edf1ffffa164264200e8031afeffe81530feff8be55dc30000ffffffff0700000053706c617368210000 }

condition:
	$a0
}

        
