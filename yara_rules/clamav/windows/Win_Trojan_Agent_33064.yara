rule Win_Trojan_Agent_33064
{
strings:
	$a0 = { ed88088a3fe0078868a64802b4ff6f2cf56c16e388db956af414901b2f08025357fa3a1bfcffff4a1830d61823947498900c4c0b6a4815ba1861db0820d7c2ffffa5febbcbc4b94169f7 }

condition:
	$a0
}

        
