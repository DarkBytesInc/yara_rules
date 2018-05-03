rule Win_Worm_Windaus_2
{
strings:
	$a0 = { ff750c5268e58040008d9df8f7ffff53e8954c000083c40853ff36e864ffffff }

condition:
	$a0
}

        
