rule Win_Trojan_Panther_1
{
strings:
	$a0 = { ec83c4f4e83533fdffe81846fdffe85372fdffe8b6ddfdffe89ddefdffe8e8fdfdffe83764feffe8be2effffe8f5a5ffffe804d1ffffa124164300e81225ffffb98c164300badcee4200a124164300e80e25ffffa124164300e89425ffffe80641fdff8be55dc38d4000000000000000000000000000 }

condition:
	$a0
}

        
