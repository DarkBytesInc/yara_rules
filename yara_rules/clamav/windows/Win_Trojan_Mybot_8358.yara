rule Win_Trojan_Mybot_8358
{
strings:
	$a0 = { 6a447d7bfeea946f109ad0f1377282f355d3962995a01782cf2ca79d544504e344c5a8a03405feef8d3c5900624a10bdb86f7eff849d3ebfe503f082ea2f9fe23bee3bcffa38c298791b7f1851f9ebb4d5cedf61aa }

condition:
	$a0
}

        
