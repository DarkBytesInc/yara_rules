rule Win_Trojan_Johanna_1
{
strings:
	$a0 = { eb04????????be1701b9bc012e812c????83c6024975f5 }

condition:
	$a0
}

        
