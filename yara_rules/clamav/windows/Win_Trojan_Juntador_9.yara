rule Win_Trojan_Juntador_9
{
strings:
	$a0 = { 5a595964891068913a40008d45f0e8b3edffffc3e9b1eaffffebf05f5e5be81ff6ffff8be55dc3000000ffffffff0a0000007365727665722e6578650000ffffffff060000005c74656d705c0000ffffffff030000004a55 }

condition:
	$a0
}

        
