rule Win_Adware_Multiplug_3
{
strings:
	$a0 = { 00000000 }
	$a1 = { 00376232323730373536323663363937333638363537323232336132303232 }

condition:
	$a0 and $a1
}

        
