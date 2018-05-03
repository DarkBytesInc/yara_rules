rule Unix_Tool_13274_1
{
strings:
	$a0 = { eb175b31c0884307895b0889430c508d }

condition:
	$a0
}

        
