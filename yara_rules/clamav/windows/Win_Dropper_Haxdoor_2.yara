rule Win_Dropper_Haxdoor_2
{
strings:
	$a0 = { 6f0100000000000000000000746563686e616c79746963732e6e65742f646f6e652e657865 }

condition:
	$a0
}

        
