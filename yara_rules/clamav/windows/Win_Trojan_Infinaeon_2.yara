rule Win_Trojan_Infinaeon_2
{
strings:
	$a0 = { 440046024a00ff0137000000010800436f6d6d616e64310004011500414e5449564952555320434f4d50494c4154494f4e0004681028059f06df02110500ff031f00 }

condition:
	$a0
}

        