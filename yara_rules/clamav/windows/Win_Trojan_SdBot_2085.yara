rule Win_Trojan_SdBot_2085
{
strings:
	$a0 = { 6d1de3f0fb0402f2ee58518b2d26f84e6baf57d4c48fb61d2d27c6ff878a92f1824a55996d355363f75e10339e37ba8f2c0d068ea27b10338c667d1009b7bb8bad82e15e8dd13f10ba39600c6fe56cd6f9a5 }

condition:
	$a0
}

        
