rule Osx_Trojan_Crisis_2
{
strings:
	$a0 = { 6261636b646f6f725f696e6974[0-200]686964655f6b657874 }
	$a1 = { 6d63686f6f6b5f7374617274 }

condition:
	$a0 and $a1
}

        
