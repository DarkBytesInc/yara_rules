rule Win_Downloader_Small_2061
{
strings:
	$a0 = { 6a006a00685810400068101040006a00e82400000085c075e76a056858104000ffd6 }

condition:
	$a0
}

        
