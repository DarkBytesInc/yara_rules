rule Win_Trojan_Lineage_62
{
strings:
	$a0 = { b19f72f9ae6c0172483fb8e2c2f4eccfcabfa24cd9c51798feaa4ddb7ae5feb778d580581851645832d00b8c192e7c334ab95467174ce8f05034668c544b7a54af340e4bd5353546185873e50974ea3d }

condition:
	$a0
}

        
