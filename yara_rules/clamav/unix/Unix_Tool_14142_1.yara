rule Unix_Tool_14142_1
{
strings:
	$a0 = { 24608fe216ff2fe1de40a0e3010c54e31eff2f81de4044e20450dee7025085e20450cee7df4084e2f7ffffeaf5ffffebff5e8de014fd2ddf76440a2efd1ffd2f0d25ffddff25ffdd }

condition:
	$a0
}

        
