rule Win_Downloader_Banload_1114
{
strings:
	$a0 = { 04d28f032513fabaec0a64da9c165daba75442d9fe77314030ac5fc30b4b5a8f7ae1cb55156366c9b7e6d20d21800ae554dec119a69c52acb584032e6d805255074c25be9049f076526953b098e5dace3246 }

condition:
	$a0
}

        
