rule Win_Trojan_Bancos_1076
{
strings:
	$a0 = { 14834ab1fa7110853d045c32bfba891f9c1aedee2d8d623f5f44600e3b8057c285328d45e6825b2f8bc5f04364faab7bd7868bc1f5d6a9ebc67a8d5b5897d39951de2c0c8bbfad2acbf5e0bf249d19d273101d2be63f386a8d17f1425c7519 }

condition:
	$a0
}

        
