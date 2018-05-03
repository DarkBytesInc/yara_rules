rule Win_Worm_Autorun_316
{
strings:
	$a0 = { 7874656d70312e657865[0-10]77696e75702e657865[0-71]7368656c6c5c4175746f5c636f6d6d616e643d }

condition:
	$a0
}

        
