rule Win_Trojan_SdBot_3909
{
strings:
	$a0 = { e0ea7fea96ea0211dbca0fd271c601aefd832e591ebe3d825374684921c15fb363bee3aa68d638f253d26e88af6fa3f3994e9f7475752e4efec8c98a64407f07e8d03855521f54cc3f3fc2c94620ad014e61fd827cb7d5d76bdee4cd }

condition:
	$a0
}

        
