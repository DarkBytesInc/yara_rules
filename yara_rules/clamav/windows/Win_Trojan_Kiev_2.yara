rule Win_Trojan_Kiev_2
{
strings:
	$a0 = { ff008018004b034e554c20202020202020fd9d5e082e8c0614002e891e1600cb0100e208ea070d07a806ee0548 }

condition:
	$a0
}

        
