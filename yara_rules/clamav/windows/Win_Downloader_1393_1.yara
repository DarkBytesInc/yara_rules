rule Win_Downloader_1393_1
{
strings:
	$a0 = { 2959a9581b60d0a4382a3b79da4cf689b69713bbb8d4d82f34234b50ed1327382394a6f47fb96c1b9f2dfe3fff8b05da51923cfb29b58651a8207b67cc9320aee8a7ef55fc025fc9fa8ddb14759ceb5e7fe2ac5ea4f42a2c82096ed8aa49cf6929cd08 }

condition:
	$a0
}

        
