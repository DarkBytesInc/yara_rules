rule Win_Trojan_Agent_34707
{
strings:
	$a0 = { eb2000007358008bd900f3000000760054b9630f3e00000000ab0000000000f41b0081c603acadc9b998 }

condition:
	$a0
}

        
