rule Win_Worm_Shatrix_1
{
strings:
	$a0 = { 68e404450068f80445008d45a8506a00e8b350fbff83c4108d8510ffffffe8b5f3ffff8b8d10ffffff8d8514ffffffba0c054500e8fb44fbff }

condition:
	$a0
}

        
