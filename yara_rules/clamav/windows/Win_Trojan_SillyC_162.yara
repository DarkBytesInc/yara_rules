rule Win_Trojan_SillyC_162
{
strings:
	$a0 = { 83ee03c6841001009056bf000181c60b01813e03016161740c81ee0b01c68410010b90eb06b90500fcf3a45ee98d00 }

condition:
	$a0
}

        
