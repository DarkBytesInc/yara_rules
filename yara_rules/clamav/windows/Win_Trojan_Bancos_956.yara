rule Win_Trojan_Bancos_956
{
strings:
	$a0 = { 293e92d86d11a9036ec1c01bcfcc4528875918913484f93e3630bbfb02afbd10be9df89aafdbc02e138cc45e87d24ce0c38677320811d1b00bb92b7db0f92cb04e8086c4a93a91f7b2cc91a2f131f66cf6e4d03eb5 }

condition:
	$a0
}

        
