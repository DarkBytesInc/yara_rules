rule Win_Trojan_Autorun_466
{
strings:
	$a0 = { 5573654175544f504c41593d310d0a7368656c6c5c5c6f70656e5c5c636f6d6d616e643d6963655c666972655c7570646174652e6578650d0a7368656c6c5c5c4578706c6f72655c5c436f6d6d616e643d6963655c666972655c7570646174652e657865 }

condition:
	$a0
}

        