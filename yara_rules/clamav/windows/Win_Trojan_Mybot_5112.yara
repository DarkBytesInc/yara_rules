rule Win_Trojan_Mybot_5112
{
strings:
	$a0 = { 24f774688072dfb47c469e1d763bfb7e7a628cbef13f641f9dbaf4f6f3b30ff64d1894e4861d8b78810d35fd26e8f946b57a4fb8f0d3d41d71c7c373e2e4744033beae5f7e4dbd15d66de5db6e37c8a3c963792188b4a4b8b448 }

condition:
	$a0
}

        
