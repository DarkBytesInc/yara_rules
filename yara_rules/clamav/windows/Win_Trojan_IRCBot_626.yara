rule Win_Trojan_IRCBot_626
{
strings:
	$a0 = { 87379abcbc533cbc4c69a41124dae9f278b9b792072539e734622eb18620de363c692e44fed998e95cf1a4282dfbf052081d5c32faf9f0a31d54f068b30b29c3d46d554baf0fd2840fc665707f4b }

condition:
	$a0
}

        
