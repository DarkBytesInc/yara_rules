rule Win_Trojan_Mybot_8261
{
strings:
	$a0 = { f15463e58bb8303350cb6d0cc32aa0544b241f7a62f1b7c616e2b2fced282aee00689ae86188e46ec8bf911c6080c111664cc46496cbc56414cbdad2241be1d4991dc986b597 }

condition:
	$a0
}

        
