rule Win_Trojan_Mybot_5922
{
strings:
	$a0 = { 60c3e7278af4a955a183fa89c269394761e226d578f4d8844b963a9657f201738aed550058940ab73073140096e8fd3d5ba87c9e16b18e }

condition:
	$a0
}

        
