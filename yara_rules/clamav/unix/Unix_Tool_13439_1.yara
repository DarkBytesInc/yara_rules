rule Unix_Tool_13439_1
{
strings:
	$a0 = { 31c031db31c931d2b046cd80eb235e88560a8d1eb00566b9040866ba9a02cd8089c3b03666b9 }

condition:
	$a0
}

        
