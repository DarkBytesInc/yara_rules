rule Win_Worm_VB_1021
{
strings:
	$a0 = { 5c00520075006e }
	$a1 = { 6e616b61746f6d79 }
	$a2 = { 6675636b5f79 }
	$a3 = { 452d365501002e455845 }
	$a4 = { 4c0049004c004900540048 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}

        
