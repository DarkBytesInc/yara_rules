rule Win_Downloader_Banload_1546
{
strings:
	$a0 = { 41fcb6abd8161ceb4902484db2ff296c11d3083e071e3810fcf606a2fa8cfc05561cf4f6e557da347696d5f10f460f72efc156dca0865207d25f274b5a409ef4ca7a4b39e3cc4913efbaf4316e0e28fdcce91d497b4cadceb202 }

condition:
	$a0
}

        
