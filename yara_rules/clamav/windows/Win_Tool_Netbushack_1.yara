rule Win_Tool_Netbushack_1
{
strings:
	$a0 = { 8811400068000000730000007e0000007f0000004e65744275734861636b004e6574 }

condition:
	$a0
}

        
