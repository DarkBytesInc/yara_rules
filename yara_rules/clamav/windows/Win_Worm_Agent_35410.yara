rule Win_Worm_Agent_35410
{
strings:
	$a0 = { 558bec6aff6820710010689032001064a1 }
	$a1 = { 6f6b61676f6b61676b6f676f6b676b6f }

condition:
	$a0 and $a1
}

        
