rule Html_Trojan_Downloader_95
{
strings:
	$a0 = { 333434343435353535363636363737373738383838393939392e776d76 }

condition:
	$a0
}

        
