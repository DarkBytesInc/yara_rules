rule Win_Downloader_976_1
{
strings:
	$a0 = { 0f80d659b6d0bcbcf1111e9c84a8edb564848656c3dcc6ff0a766e67a0537cd5e959dccc454db670bb03e1ae0d0d04a82de08d0b283f6d6c6619b9d0efe1ca62cccc895a53104347fd5408c0db379af20d84b641a75f10b830b2da15 }

condition:
	$a0
}

        
