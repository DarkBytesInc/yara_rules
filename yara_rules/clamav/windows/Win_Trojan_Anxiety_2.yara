rule Win_Trojan_Anxiety_2
{
strings:
	$a0 = { b9040000008b9782254000b800d600008db7ca254000cd2032004000813e504500000f8547020000 }

condition:
	$a0
}

        
