rule Win_Trojan_Win_43
{
strings:
	$a0 = { d80000cd20320040000f82a101000066813e4d5a0f8596010000817e28000ff0000f84890100 }

condition:
	$a0
}

        
