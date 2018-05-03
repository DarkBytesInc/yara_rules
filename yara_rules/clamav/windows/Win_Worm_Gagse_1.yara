rule Win_Worm_Gagse_1
{
strings:
	$a0 = { 6cb347b7128ada1b2bef2f2b019f62f9bf6a6e6e61725c4c47616773655ce7cc310003ffffffff2ef68417fedbcd48 }

condition:
	$a0
}

        
