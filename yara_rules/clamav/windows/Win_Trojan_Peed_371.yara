rule Win_Trojan_Peed_371
{
strings:
	$a0 = { 81c78104000081ff81040000741f81ff0dd000007f17b95f3d12ff4881c10fd0ed00ba????????c1ca0289d6c3e8e4ffffff52ad05????????eb2ce2f6c3cd2dab50525131c089c15151ff15????????0528d1030093595a5801df83ef0581ef27d10300 }

condition:
	$a0
}

        
