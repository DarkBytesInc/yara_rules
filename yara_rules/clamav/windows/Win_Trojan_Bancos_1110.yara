rule Win_Trojan_Bancos_1110
{
strings:
	$a0 = { ee99ad24a4d1e01fcabbf7edb112b8e117a16e3793a3f5f4c0c161a5c376fa4fd28cf976519473a91f6397badde8f24219dbf3305aa10290f8990e15fe55cb40684e66e2169217146397ff2bfb9900bffe7d81fafa7f4ea3d1611b359e7f2c10e88ef18a25ddbcf7eb53ace0d34f }

condition:
	$a0
}

        
