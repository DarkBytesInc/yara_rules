rule Win_Downloader_994_1
{
strings:
	$a0 = { dcfca66b45b369eb7d1706d4938e8666f1a2696ec5e973d5ed0a336a84633b7ae70b477ecdb78c283ba2284414ffe196e9b627ddb52a6790f60937860ebae7c88eae671cbcb052fdcd839fcdcd55da6aeef920feb5f38eb36b10fbe3 }

condition:
	$a0
}

        
