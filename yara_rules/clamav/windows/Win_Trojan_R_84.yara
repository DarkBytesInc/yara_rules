rule Win_Trojan_R_84
{
strings:
	$a0 = { 350889363908893e37088c063d088c1e3b080e1f0e07b81111ba0100b90100cd1502e086e032e4056900fecc93b9 }

condition:
	$a0
}

        
