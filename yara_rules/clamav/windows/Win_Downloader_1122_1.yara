rule Win_Downloader_1122_1
{
strings:
	$a0 = { 427373ebf76201f4cd103648e890945fb98625ebeee6524cf4f006fcbef62be8d80de2ea1474e8db758a3a5e104ec1c9edb7e93e79ea4bf8e84748b1bf1b85e03684c0b898085bc3aa85aa4bbdcd3aa84c3a02fa8f69e1c755b5dedf }

condition:
	$a0
}

        
