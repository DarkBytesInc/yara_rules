rule Win_Trojan_SdBot_2665
{
strings:
	$a0 = { 6180948f37937955df95c7efcb5e8b474a6c527952f5ebc5752fae3200eaf810e88ef093ab8c0a95ec9eb896df0f2985e86acdefec1eacd052daaeb318881b43c2595ec11535a91bf1d6fdd1c774ec6316210c17c46cea }

condition:
	$a0
}

        
