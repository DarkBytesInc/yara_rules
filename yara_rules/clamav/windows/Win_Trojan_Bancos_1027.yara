rule Win_Trojan_Bancos_1027
{
strings:
	$a0 = { a45b634d2cf152d46fd0039da2e974fb9787ea2a7b4e4823e274aa1b77cb3d44293fcf0bbee94e8ac15de51b1575aa8486179b694e3628f804a97bfd81fa5da5eafad847c69b304311c4bcdec599c1dfee61673902b150dc }

condition:
	$a0
}

        
