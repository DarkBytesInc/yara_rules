rule Win_Downloader_Small_2540
{
strings:
	$a0 = { e581ec9400000081ecfc0c000089e3041d89258b4e4000a14a60400080ec1589834b060000a14660400080c16d8983bd }

condition:
	$a0
}

        
