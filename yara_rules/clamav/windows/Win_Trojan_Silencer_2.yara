rule Win_Trojan_Silencer_2
{
strings:
	$a0 = { 53696c656e636572000000000000000000000000ffcc31001ee2b20edf4aa1d211abf8d8158c9a2932e3b20edf4aa1d211abf8d8158c9a2932724fad339966cf }

condition:
	$a0
}

        
