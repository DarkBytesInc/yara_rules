rule Win_Trojan_VB_1071
{
strings:
	$a0 = { 2a0044006f0065006e006500720020005300610076006100670065002a }

condition:
	$a0
}

        
