rule Win_Trojan_Gbot_16
{
strings:
	$a0 = { 55fc8bec81c4a0fbffff68003000006aff506affe84200000083e80303d10fafc2678d16060025ff00000084c07477b8570000006a006a00f2ff15????41003c }

condition:
	$a0
}

        
