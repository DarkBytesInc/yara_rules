rule Win_Trojan_W_141
{
strings:
	$a0 = { feffff0f82d000000033c10f85c800000066813e4d5a0f85bd0000008b463c03f03d840300000f83ad000000813e504500000f85a1000000b8533333213946588946580f849000000066817e044c010f85840000000fb74616f6d0a90220000075770fb74606486bc0288dbe }

condition:
	$a0
}

        