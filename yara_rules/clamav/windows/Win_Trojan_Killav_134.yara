rule Win_Trojan_Killav_134
{
strings:
	$a0 = { 6e65742073746f702041434b57494e3332[0-1]6e65742073746f7020414456584457494e }

condition:
	$a0
}

        
