rule Win_Trojan_Cubi_1
{
strings:
	$a0 = { 53756220[0-25]7061796c6f6164200d0a456e6420537562200d0a200d0a27202f2f20456e64206f6620 }

condition:
	$a0
}

        
