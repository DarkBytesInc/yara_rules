rule Win_Spyware_57520_1
{
strings:
	$a0 = { 558becb854105897bb0928d16f50e800000000582da81a0000b96d1a0000ba211b0000be00100000bfc053 }

condition:
	$a0
}

        
