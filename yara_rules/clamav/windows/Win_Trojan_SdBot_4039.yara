rule Win_Trojan_SdBot_4039
{
strings:
	$a0 = { 8f0ecf93302b79431ba5885f5db88ed5f1f18f94050de08ec553b8c3b692ee0fc488e33227bc4a1ef721b1725f11eb98b78a4fdfaeec804d907b9eebc0d456521059887169835ae6657aa4d34963a99f1ccf202cb1a6 }

condition:
	$a0
}

        
