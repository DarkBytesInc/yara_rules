rule Win_Trojan_Mybot_6269
{
strings:
	$a0 = { fb70db7ff4ffffca3b06665c0b0111ff9e658f69ae62f8d3ff6b61896c1678e20affffffffa0eed20dd75483044ec2b30339612667a7f71660d04d476949db776e3e4a6ad1c0ffffffaedc5ad6d9660bdf40f03bd83753aebca9c59ebbde7fcfb247e9ffff1fd8491cf2bdbd8ac2baca3093b353a6a3 }

condition:
	$a0
}

        
