rule Win_Worm_Autorun_372
{
strings:
	$a0 = { 2e646c6c[0-10]5348414e4742414e4441434845[0-10]4155544f52554e2e494e46 }

condition:
	$a0
}

        
