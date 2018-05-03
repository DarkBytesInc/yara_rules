rule Email_Trojan_Trojan_564
{
strings:
	$a0 = { 476f6f64206576656e696e672c206f6c6420636861702e0d0d5761746368206d79207469747321 }

condition:
	$a0
}

        
