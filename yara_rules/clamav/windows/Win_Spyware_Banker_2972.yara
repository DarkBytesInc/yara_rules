rule Win_Spyware_Banker_2972
{
strings:
	$a0 = { 596bcaad163e4c221aadb1b7be4a1f95f273d51e7af78d8ec3b9906a0510a72f83f3db27132925fdc9db9a6bc2d50a97f02e42e28c6ca30991a76cacc0f85a58abfbd97f01ea703be121bacac3675a22f3eed261683abd02131891ca3cf71f2333f9f94a }

condition:
	$a0
}

        
