rule Win_Trojan_Gega317_1
{
strings:
	$a0 = { 6821000000cd208f0001000f82d100000066813d4a0200004d5a0f84ab000000b8003f0000b90200 }

condition:
	$a0
}

        
