rule Win_Trojan_Mybot_7989
{
strings:
	$a0 = { 8d744fe6bd16f7682f4e75eb1e4ac3229c62ebffa8d4943a0db05b6e6fa95a76337380b702ca30c8fed2b391cec053cb9af38ff7a98ea36f23821b2784cafb56d53342c3c1651c7e7d14165ab65b8eae7f57c44ed1b1274558acd585b80b77be2dd96987abeaaaa1dbfdc4a0bb92 }

condition:
	$a0
}

        
