rule Win_Trojan_BusMouse_1
{
strings:
	$a0 = { 012e891e06012e890e08012e89160a012e89360c012e893e0e012e892e10012e892612012e8c1e14012e8c0616 }

condition:
	$a0
}

        
