rule Win_Trojan_VBS_205
{
strings:
	$a0 = { 22736372697074696e672e66696c6573797374656d6f626a }
	$a1 = { 7479207761726e696e67 }
	$a2 = { 6e6f626f647920776f756c64206b6e6f77 }

condition:
	$a0 and $a1 and $a2
}

        
