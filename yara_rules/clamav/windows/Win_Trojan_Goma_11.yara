rule Win_Trojan_Goma_11
{
strings:
	$a0 = { 03008986d202b2e98896d102b96101b4408d960301e84b0033d233c9b80042e84100e82c008d96 }

condition:
	$a0
}

        
