rule Win_Trojan_Agent_34569
{
strings:
	$a0 = { 333630747261 }
	$a1 = { 2650494e3d257326523d25732652473d2564264d3d2564264d313d2564266d6163 }
	$a2 = { 000000005241566d }

condition:
	$a0 and $a1 and $a2
}

        
