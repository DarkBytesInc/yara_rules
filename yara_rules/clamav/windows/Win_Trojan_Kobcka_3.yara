rule Win_Trojan_Kobcka_3
{
strings:
	$a0 = { 8d1de8593f0081eb6249ffff8d05b93b3f0005b0da0000ffd003d88d8b5282ffff81c1ae7d0000ffd18d15322f3f0081eaa21affffffd28d8c2484e9ffff89817816000083c4fc8d0d785f400081c1fcb4ffffffd1c3e81f060000c38d053c813f000550 }

condition:
	$a0
}

        
