rule Win_Trojan_Vgen_115
{
strings:
	$a0 = { 5e81ee0801eb0a905669636f64696e45532bff8beee962015461726765742e506f707079000000003d004b740d3d }

condition:
	$a0
}

        
