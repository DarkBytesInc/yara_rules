rule Win_Trojan_VGEN_384
{
strings:
	$a0 = { 0dcd21b452cd21fc26c57712c534bb02008cd83b34750a3b3074043b007502eb788b383b3575098b19895c028937eb }

condition:
	$a0
}

        
