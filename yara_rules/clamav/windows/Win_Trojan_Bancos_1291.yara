rule Win_Trojan_Bancos_1291
{
strings:
	$a0 = { fa8c7ff58a5b576dee7dc7985a7fec45d46e4312de43fe465d7ee3ee8ea04f4d5c595312365bf393a44bbcbd129578c0128635fc0e7c58d6bfe6fa01a763f62066825a2b507b364c70a23962dce6d3da3c534b98 }

condition:
	$a0
}

        
