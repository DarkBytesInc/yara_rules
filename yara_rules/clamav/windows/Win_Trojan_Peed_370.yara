rule Win_Trojan_Peed_370
{
strings:
	$a0 = { 81c78104000081ff81040000744881ff0dd000007f40b95f3d12ff4881c10fd0ed00ba????????c1ca0289d6c3cd2dab50525131c089c15151ff15????????0528d1030093595a5801df83ef0581ef27d10300e2dac3e8bbffffff52ad05????????eb03 }

condition:
	$a0
}

        
