rule Win_Trojan_Spambot_169
{
strings:
	$a0 = { 1145c29f520b516e06be3e88daad821ffeeb3ff124ffffffff46d663b4bbd711101925f3c305ec68268acaa4f7a188bc57b8cf2e3893034bf8fffffaff9ef9805809f37bb3f8fd9b9ff051177469b6fd63cf0d8dc667d7ffffffff5c623cb94fd9b959eead21ae15c1abd4d29ced }

condition:
	$a0
}

        
