rule Win_Trojan_Mybot_6357
{
strings:
	$a0 = { 785e0b0a61aaac74d4db3b600a0f7fc0b2ff11edf6657904d43d84b3b1fc38426f345041c143ca6deb7c1a8dd5f7b769f7bba64b443b7b47ba6a599bdf6e5cc27b47bfbeca090e39f430140b24ce7620e8a2bd97d4f68bfc8665b46a01f08a51e2b3958ec1105eedbb5414ab5dedb214fdfd605571533381189418d4a7080082bd72108749e2d4d8b8e829ea7baf27945e15ec09a4b1 }

condition:
	$a0
}

        