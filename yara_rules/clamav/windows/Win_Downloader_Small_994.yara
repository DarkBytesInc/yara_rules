rule Win_Downloader_Small_994
{
strings:
	$a0 = { 69616c312e6578650000006e65776469616c2e747874005c6e65776469616c2e657865000000007061796469616c2e747874005c7061796469616c2e6578650000000070617974696d652e747874005c70617974696d652e65786500000000746962732e706870000000005c746962732e657865000000746f6f6c332e7478740000005c746f6f6c332e6578650000746f6f6c322e74 }

condition:
	$a0
}

        