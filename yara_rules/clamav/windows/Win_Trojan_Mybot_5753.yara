rule Win_Trojan_Mybot_5753
{
strings:
	$a0 = { 9b0c67d6d759675290917d4ab46f010ffa9f83a66aac45cc03f498b7299b0599bc480209fedc30a36ac58852a652bb578810b095f7f69e4022525de8d8f44dc17e16681f91c1b0b90a7cbb3cd979fdaf4f59b20b24678d67d42cff8a109c757e2ade0d090cb4bc66c2e0af7ae6cd91d0dff50b890b4882ef3ab1c312f22f9eed92c4ef3a902fb4ea98ca9c7a }

condition:
	$a0
}

        