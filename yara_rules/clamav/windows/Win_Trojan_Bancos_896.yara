rule Win_Trojan_Bancos_896
{
strings:
	$a0 = { 88c5a8e4281164aa9965f07727b3af5b5b3363409d2bb0ff326dbd6d66ca1a857c01c8a046dfea1b7ca9cdefc7de564fe9fddb280aaa8d9b193fabd9467ed24e5ecb30e66cadc4dce19f567a5823210b6d1313071efd4612f734fcebefb438cd }

condition:
	$a0
}

        
