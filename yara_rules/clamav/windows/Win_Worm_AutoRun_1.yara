rule Win_Worm_AutoRun_1
{
strings:
	$a0 = { 5b6175746f72756e5d[0-101]7368656c6c5c6f70656e5c436f6d6d616e643d6175746f706c792e657865 }

condition:
	$a0
}

        
