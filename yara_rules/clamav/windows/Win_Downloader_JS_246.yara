rule Win_Downloader_JS_246
{
strings:
	$a0 = { 6361746368286529207b77696e646f772e6c6f636174696f6e3d272f273b7d7d7d7472797b6576616c28276e73686b28293b27297d6361746368286529207b616c657274282765727227293b7d223b6576616c28746e777a6976293b3c2f7363726970743e }

condition:
	$a0
}

        