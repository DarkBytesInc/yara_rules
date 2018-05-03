rule Win_Worm_Autorun_220
{
strings:
	$a0 = { 5b6175746f72756e5d }
	$a1 = { 5c43757272656e74436f6e74726f6c5365745c53657276696365735c4b34686f7374454c }

condition:
	$a0 and $a1
}

        
