rule Win_Tool_WM_7
{
strings:
	$a0 = { 0800550014000100ffff000000008c0200000a0000002603 }

condition:
	$a0
}

        
