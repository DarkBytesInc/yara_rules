rule Win_Worm_Gaobot_265
{
strings:
	$a0 = { f9204a4f494e41676f62fe4d9801b45551205539f7876d3e2573044f66666c69fb1bd74588b8056374 }

condition:
	$a0
}

        
