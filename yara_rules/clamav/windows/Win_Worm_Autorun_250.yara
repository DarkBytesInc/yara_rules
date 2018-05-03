rule Win_Worm_Autorun_250
{
strings:
	$a0 = { 7368656c6c657865637574653d6d7920646174612e626174 }

condition:
	$a0
}

        
