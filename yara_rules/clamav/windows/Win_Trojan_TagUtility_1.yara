rule Win_Trojan_TagUtility_1
{
strings:
	$a0 = { 9a0000c4009a00005e0089e581ec000131c0a30001a100014099bf00009a8502c400a30001833e0001017515bf08000e }

condition:
	$a0
}

        
