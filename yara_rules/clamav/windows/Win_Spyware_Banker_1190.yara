rule Win_Spyware_Banker_1190
{
strings:
	$a0 = { b4ca13412ecbe786d697238151e41541b18ea007b94fa54c74f3ce39cc89d58a7046ce2c07f2d11e4d67502d5cda0051a2e0730d1ff8f1a5918d2bdd226cd206ebcf2a2f8dfde3d6bcfef7a342946553a15f6d9704ffd0476dc9 }

condition:
	$a0
}

        
