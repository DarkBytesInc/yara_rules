rule Win_Trojan_Trojan_274
{
strings:
	$a0 = { c100b838002689078cc8268947025b5807c350531e06b82135cd212e891e32002e8c0634000e1f }

condition:
	$a0
}

        
