rule Win_Trojan_Banload_2115
{
strings:
	$a0 = { 0f84910000008b4db48d9570ffffff518d45dc5250c78578ffffff0100000089bd70ffffffffd38b4dc85051ff15??1040008bd08d4d84ffd650ff15??10400050ff15??1040008bd08d4d80ffd650ff15??1040008bd08d4db4ffd68d5580 }

condition:
	$a0
}

        
