rule Win_Trojan_Gbot_6
{
strings:
	$a0 = { 558bec81eca401000083e000505050[0-16]e8580000002683c0fdf8660fafc2ba0600000025ff0000002e6683f8a7fcf27461546a }

condition:
	$a0
}

        
