rule Win_Downloader_1095_1
{
strings:
	$a0 = { a6ca307d220d85426f85d02ab1b5785e5508e8c24b096eb1965ab50f1d42efc36ce8f7e1c4b8e6b65635bc306de6301ee65dbf08ac7a2b5472aea7eba169105b8b42e9cd4cc16ed0a52783e94073c6d052f5b74329766db52151ee70 }

condition:
	$a0
}

        