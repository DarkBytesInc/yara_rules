rule Unix_Tool_13697_1
{
strings:
	$a0 = { 6a0b58995266682d7089e1526a68682f626173682f62696e89e352515389e1cd80 }

condition:
	$a0
}

        
