rule Win_Trojan_Small_4485
{
strings:
	$a0 = { 5589e56a0089e7b8??324200abe81a000000e820000000adf7da29d035 }

condition:
	$a0
}

        
