rule Win_Downloader_Small_2240
{
strings:
	$a0 = { e5b64481ec9400000081ecfc0c000080c44189e380c6358925db344000a1446040008983f10c0000a148604000898379040000c7834009000000000000b624b6c5c783520a00000000000080e1cec7837a0a }

condition:
	$a0
}

        