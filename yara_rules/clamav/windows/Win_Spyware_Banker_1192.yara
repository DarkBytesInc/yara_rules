rule Win_Spyware_Banker_1192
{
strings:
	$a0 = { 4d92a69f1b9f796ca42a2c810b281ef84dc419fc5d82e53ba8220e2aca22ec91dba0dd69797512786de69e2be3fbac709e561f38335a75ccfa9a9f27ee1afb60955ac0e973e38b7cf11abf3dda7e3cb2ee80383c616537fdd57f }

condition:
	$a0
}

        
