rule Win_Trojan_Peed_368
{
strings:
	$a0 = { 0fc1c3b9881300004981e9a00f000081e9e703000051680000c8ff68f54ff0ff6889b80f00e85400000089cab812??99f49681c6ee45b30b89f756eb01c3e819000000e81f00000081c3????????e814000000e80d000000e2e4ebe16affe859000000ad }

condition:
	$a0
}

        