rule Win_Downloader_Small_1488
{
strings:
	$a0 = { 757365722031203120200d0a6765742065726173656d655f??????????2e65786520200d0a7175697420200d0a }

condition:
	$a0
}

        
