rule Win_Trojan_1stVir_1
{
strings:
	$a0 = { c606f70b009050538cd08cc33bc35b5875102ec606f70b01902e803ef80b017401585053515256571e06e8c809071f }

condition:
	$a0
}

        
