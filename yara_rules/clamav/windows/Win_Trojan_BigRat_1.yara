rule Win_Trojan_BigRat_1
{
strings:
	$a0 = { ba82010500003b060200731a2d2000fa8ed0fb2d19008ec050b9c40033ff57be4401fcf3a5cbb409ba3201cd21 }

condition:
	$a0
}

        