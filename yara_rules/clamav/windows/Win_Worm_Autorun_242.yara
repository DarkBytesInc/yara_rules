rule Win_Worm_Autorun_242
{
strings:
	$a0 = { 5b4175746f52756e5d[0-133]7368656c6c5c6f70656e5c436f6d6d616e643d696e666f626f6f742e657865 }

condition:
	$a0
}

        
