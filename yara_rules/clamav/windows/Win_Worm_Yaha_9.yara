rule Win_Worm_Yaha_9
{
strings:
	$a0 = { 504f626f78207149e7dc6574d9c6aa303358af03414f4c203774b45166c6e294d43f5553f5317562e23035cd33 }

condition:
	$a0
}

        
