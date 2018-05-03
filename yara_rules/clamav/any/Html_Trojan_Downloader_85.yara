rule Html_Trojan_Downloader_85
{
strings:
	$a0 = { 7365742532307061737461[0-57]7373767373657276696365732e657865 }

condition:
	$a0
}

        
