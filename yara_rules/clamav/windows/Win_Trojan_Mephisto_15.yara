rule Win_Trojan_Mephisto_15
{
strings:
	$a0 = { e800008bfc368b2d81ed0301e9de00414c4c20474f4f44205448494e4753204d55535420434f4d4520544f20414e2045 }

condition:
	$a0
}

        
