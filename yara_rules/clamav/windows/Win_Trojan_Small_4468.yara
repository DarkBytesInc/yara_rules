rule Win_Trojan_Small_4468
{
strings:
	$a0 = { ff74241c588d80??????04506862343504e8??00000040508d15??????0a5250 }

condition:
	$a0
}

        
