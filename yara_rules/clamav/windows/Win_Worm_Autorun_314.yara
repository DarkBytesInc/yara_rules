rule Win_Worm_Autorun_314
{
strings:
	$a0 = { 7368656c6c5c6f70656e5c436f6d6d616e643d52454359434c45525c6175746f706c61792e657865 }

condition:
	$a0
}

        
