rule Win_Trojan_Mshark_6
{
strings:
	$a0 = { ee03008b84fe002ea300018aa400012e88260201eb039033f6e83403061e33c08ec026813e80024d737503e98d00 }

condition:
	$a0
}

        
