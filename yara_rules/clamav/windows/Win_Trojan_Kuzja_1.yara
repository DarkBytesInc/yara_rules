rule Win_Trojan_Kuzja_1
{
strings:
	$a0 = { 5c53797374656d526573746f72655c44697361626c655352[0-152]4b757a6a61205265706f7274 }
	$a1 = { 7461736b6b696c6c }

condition:
	$a0 and $a1
}

        
