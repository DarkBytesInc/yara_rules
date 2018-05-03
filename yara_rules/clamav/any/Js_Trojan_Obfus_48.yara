rule Js_Trojan_Obfus_48
{
strings:
	$a0 = { 255044462d }
	$a1 = { 66756e6374696f6e20 }
	$a2 = { 646f207b[30-80]696e6465784f66[5-30]636861724174 }
	$a3 = { 537472696e672e66726f6d43686172436f6465 }

condition:
	$a0 and $a1 and $a2 and $a3
}

        
