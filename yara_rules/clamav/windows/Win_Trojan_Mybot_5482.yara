rule Win_Trojan_Mybot_5482
{
strings:
	$a0 = { 49ba9c4fa1fbc3f37163843ddd5b228cebf85700171f39083521f7a1c73f22b2ec3d03c5b3a975851b419801d93c6712096f9844abaf9aae3f19749015dfaeadc8c8f0040986 }

condition:
	$a0
}

        
