rule Win_Trojan_Trash_2
{
strings:
	$a0 = { 8cd80510002e0106660131c08ed8803e0e04937503eb480806575651a113042d3000b106d3e02d10008ec0500e1f }

condition:
	$a0
}

        
