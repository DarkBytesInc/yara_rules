rule Win_Trojan_VB_1121
{
strings:
	$a0 = { 68081d4000e8f0ffffff0000000000003000000040000000000000007a9ce46de9e7e44696e59e8a74f55909 }

condition:
	$a0
}

        
