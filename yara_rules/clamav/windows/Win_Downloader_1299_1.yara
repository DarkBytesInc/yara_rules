rule Win_Downloader_1299_1
{
strings:
	$a0 = { 8d8df0fdffff6a038d95f4feffff5152e821010000bf9003151383c9ff33c083c40cf2aef7d12bf98d95f4feffff8bf78bd98bfa83c9fff2ae8bcb4fc1e902f3a58bcb5083e1038d85f4fefffff3a450ff152402151368f4010000ff1520021513 }

condition:
	$a0
}

        
