rule Win_Trojan_FakeAlert_13
{
strings:
	$a0 = { 219574ffffff8995b4feffff0195fcfeffff0b55ac2b9530feffff319548ffffff119580ffffffff8d28feffff4a31ca4281fa4a020000753a0b8d5cffffff1b9538ffffff8b8d04ffffff198df4feffff294d98114da4098d50ffffff01ca09953cffff }

condition:
	$a0
}

        
