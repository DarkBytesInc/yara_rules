rule Win_Downloader_Banload_2062
{
strings:
	$a0 = { b75c243000e001008bc31b445bc363a890410619a4a09c6498949097fff6938c56bed000000000556c833e00753a6844066a00deddfe3fa88bc885c9750533c05e64a1cc20890100000416890dff0733d28bc203c08d44c1048b1e89188906000000004283fa6475ec8b068b1089167fffde762b9089294004c3578bf28bd84ae885c000000000dbb7ff6048 }

condition:
	$a0
}

        