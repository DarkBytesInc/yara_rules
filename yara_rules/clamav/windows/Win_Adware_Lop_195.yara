rule Win_Adware_Lop_195
{
strings:
	$a0 = { b2668f518646a0a72a5645bdcbd098383ad768c450b923a8f3ea5ea877a81116fc894a00e923ec9e45728b136fd0a89b72954740f883fe36bd2860b6 }

condition:
	$a0
}

        
