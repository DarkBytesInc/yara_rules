rule Unix_Tool_13452_1
{
strings:
	$a0 = { 31c931c050b01750cd8051b11e6a2ee2fcb11efec9fe040cfec9e2f754b03d50cd80 }

condition:
	$a0
}

        
