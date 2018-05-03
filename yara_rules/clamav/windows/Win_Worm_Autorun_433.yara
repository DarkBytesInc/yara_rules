rule Win_Worm_Autorun_433
{
strings:
	$a0 = { 2a2e75627465 }
	$a1 = { 7368656c6c5c6578706c6f72655c436f6d6d616e643d25732573 }
	$a2 = { 5b4175746f52756e5d }

condition:
	$a0 and $a1 and $a2
}

        
