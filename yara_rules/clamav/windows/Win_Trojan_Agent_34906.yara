rule Win_Trojan_Agent_34906
{
strings:
	$a0 = { 836c8cd2ab19b6d4bc41bacf7765d736bc3fcf48a665de348e00addcaa1bbec3b000b197970a20b2d898abfbb608d7ebc63dbadab61b20c8a294ba97891db0b8bd1aadbe9a0eb3dbf9478de79a46ffffbc03090e77daaf9efa58 }

condition:
	$a0
}

        
