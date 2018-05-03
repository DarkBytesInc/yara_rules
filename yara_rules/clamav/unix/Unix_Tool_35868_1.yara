rule Unix_Tool_35868_1
{
strings:
	$a0 = { ffff0628ffffd004ffff05280110e4270ff08424ab0f02240c010101 }

condition:
	$a0
}

        
