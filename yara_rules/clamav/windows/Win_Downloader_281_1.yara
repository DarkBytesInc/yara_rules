rule Win_Downloader_281_1
{
strings:
	$a0 = { 57904c6d9276ab7dfe80692fa577c483817c22fcad92de968d97272e8e8ed53287a03aa4a2a526ac2eaf8f84d7644b0d8fa6ac7bbe9fa4708832a947ecb70f254466a596474da021f21fbe925f59 }

condition:
	$a0
}

        
