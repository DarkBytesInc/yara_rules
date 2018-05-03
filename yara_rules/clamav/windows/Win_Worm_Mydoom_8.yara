rule Win_Worm_Mydoom_8
{
strings:
	$a0 = { 7b4cbbc4fbadf0be4cd804731338beb7c06edcb5976d996df95a7c143121ff34f07661fb21a575028bde1346d67cc1531dacc176734559a426d857c8ee }

condition:
	$a0
}

        
