rule Unix_Tool_13422_1
{
strings:
	$a0 = { 9952682f2f7368682f62696e89e3525454596a0b58cd80 }

condition:
	$a0
}

        
