rule Win_Trojan_Trojan_38
{
strings:
	$a0 = { a8671137402f4bfc265e73004bfb322e72019a855249564d5347fb6219a13a6f6e1cc51c42732e5fe2c4ae9040ab917aa792798719202d3d9c }

condition:
	$a0
}

        
