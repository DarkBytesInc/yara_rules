rule Win_Trojan_Iframe_39
{
strings:
	$a0 = { 333630302c31333232352c393830312c31323939362c3131303235 }
	$a1 = { 76617270696e61 }
	$a2 = { 6d6174682e7371727428615b705d29 }

condition:
	$a0 and $a1 and $a2
}

        
