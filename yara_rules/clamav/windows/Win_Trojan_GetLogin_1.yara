rule Win_Trojan_GetLogin_1
{
strings:
	$a0 = { f9e1f1f1f8740d40e7fd53c39e8dfddb2055f53f8a0be04149fdcc3f5340e7fda9a874370c59a0a11ce6b87f82fcff8a1074370c5353c3ff8bfd141ecc3f5d2afd14f94700ff5d2afde0f8a1a0a73c47fdc24567fd6300e1edfe8ce8c3fd8bfd146a4bc34567fd46f9ff6300e1edfe8cfd147b5c29fd742747fdbdcc36 }

condition:
	$a0
}

        
