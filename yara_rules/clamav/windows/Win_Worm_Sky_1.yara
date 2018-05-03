rule Win_Worm_Sky_1
{
strings:
	$a0 = { 706f7374[0-16]74706f7374696e672e706870 }
	$a1 = { 2e6f70656e28226765[0-16]5f61646d696e2e706870 }

condition:
	$a0 and $a1
}

        
