rule Win_Downloader_Small_4651
{
strings:
	$a0 = { 6770617905ff7ff7ff6f2e756b2f00acce1069081fc27a058a03591b8092fdb0aed1976e96eeffff062f5a2806d686864ec555830038322e3137390330316efbbfed2b2575 }

condition:
	$a0
}

        
