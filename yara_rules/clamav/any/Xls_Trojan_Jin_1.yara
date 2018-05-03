rule Xls_Trojan_Jin_1
{
strings:
	$a0 = { 2f5cff29040078ff18ff3618004cff3cff2cffd0fe38fe28fe18fe08fef8fde8fdd8fdc8fd00020002000afc6704fffcf6e0fe000b0468fffe7360ff4e }

condition:
	$a0
}

        
