rule Win_Trojan__1373_0002_003_1
{
strings:
	$a0 = { 962602e82a00b440b92a018d960501cd21e81c00b800422bc999cd21b440b904008d96b301 }

condition:
	$a0
}

        
