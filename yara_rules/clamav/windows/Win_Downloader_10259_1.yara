rule Win_Downloader_10259_1
{
strings:
	$a0 = { 6860ea00006a016a00e8a4c3ffffbe9c674000a110d7400050e8dcf4ffff85c075356a006a005668e467400068446740006a00e8baf4ffff }

condition:
	$a0
}

        
