rule Win_Trojan_Izvrat_1
{
strings:
	$a0 = { 4a06ba55010500003b060200731a2d2000fa8ed0fb2d19008ec050b9c70033ff57be4401fcf3a5cbb409ba3201cd21 }

condition:
	$a0
}

        
