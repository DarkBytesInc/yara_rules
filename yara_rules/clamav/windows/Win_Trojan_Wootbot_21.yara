rule Win_Trojan_Wootbot_21
{
strings:
	$a0 = { 8f0f032a782b9d0621a9f7f7487c595ecf427b50b90ed7884549e025d37c05e150f57ffff996f7e3255558358a94efeb9d2473dedaf905b89808de058c834b598a983669078f402811357243daef2fe4123e1d390b284f829869d86d6f7909fbfd3c6203cce65b7a634d107b197e275dd86910ed1cc760475214fb95cf2efdd9119868b39b211826f9f4396b432643b0 }

condition:
	$a0
}

        