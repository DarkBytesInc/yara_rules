rule Win_Trojan_Chamber_2
{
strings:
	$a0 = { 3200000054736b48397800004765745368697400446f776e6c6f61645f436f6d706c6574656400001400540000000200000000003400030034000300233dfbfcfaa06810a73808002b3371b5223dfbfcfaa06810a73808002b3371 }

condition:
	$a0
}

        