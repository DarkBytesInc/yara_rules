rule Win_Downloader_Small_1356
{
strings:
	$a0 = { 696f6e446c6700000026636f6465323d0026636f6465313d00646c756e69712e7068703f6164763d005c6d73312e657865000000005c686f737473000070617974696d652e747874005c70617974696d652e6578650000000073656375726533322e706870000000005c73656375726533322e68746d6c000069742e74787400005c636f756e7472796469616c2e6578650000000074 }

condition:
	$a0
}

        