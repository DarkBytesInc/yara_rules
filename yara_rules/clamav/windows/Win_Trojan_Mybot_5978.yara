rule Win_Trojan_Mybot_5978
{
strings:
	$a0 = { cf8bd020cbe91649abc569dadfb0a25ad7836d4da34635742bea1c1c38fd53fbd558b4b8b99ed507de32f8933b6cb98fc75d235d67bd339237e80b5a829be933982d587db149478bd764d45c3dc6fb07373ccbbd69 }

condition:
	$a0
}

        
