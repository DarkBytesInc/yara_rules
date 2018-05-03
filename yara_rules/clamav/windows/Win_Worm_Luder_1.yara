rule Win_Worm_Luder_1
{
strings:
	$a0 = { 25d4bf86f691b870e03a8ba1e993bd0000bf6f57696e33322e4475656c202863 }

condition:
	$a0
}

        
