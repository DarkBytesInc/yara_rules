rule Win_Trojan_IRCBot_181
{
strings:
	$a0 = { b2538c5df759050db5d9ea7fd2febf4f3f72426759926cb4679586baab0356dca9e8126e83b7072580c71ff5f309cec3ccbced9c2bb3e9846da20fa5c2a47f503edd7a2797f8252d2a45b2b2f1c955abc5e699eb578e435b861a24d5353a }

condition:
	$a0
}

        
