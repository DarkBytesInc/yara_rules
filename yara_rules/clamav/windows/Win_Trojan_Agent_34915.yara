rule Win_Trojan_Agent_34915
{
strings:
	$a0 = { f70619f8f67401deb382f0156a246098e8230f8dbc75ccc6c4a220cfa66b6ff58c0760a4e43592d4800b1698803b2ed250e22a7a855b5bccac275ed004fb3460d03a2788ed7a2dc5f87466af8c899fd5043b2fe3bec715f6f673 }

condition:
	$a0
}

        