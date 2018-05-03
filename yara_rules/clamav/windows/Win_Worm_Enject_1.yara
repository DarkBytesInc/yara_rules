rule Win_Worm_Enject_1
{
strings:
	$a0 = { 50683c6e4000ffd78bd08d4dc0ffd6506a22ffd38bd08d4dbcffd650ffd78bd08d4db8ffd65068ac6e4000ffd7 }

condition:
	$a0
}

        
