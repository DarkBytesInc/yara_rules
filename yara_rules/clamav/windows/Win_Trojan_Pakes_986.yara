rule Win_Trojan_Pakes_986
{
strings:
	$a0 = { 6033c0056c6c0000500509fd2d645005fe0f40ff508bc46a006a0050e8????000083c40c83f8017c1166b9504503403c }

condition:
	$a0
}

        
