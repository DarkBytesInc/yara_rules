rule Win_Worm_Lovgate_30
{
strings:
	$a0 = { df233f48ed5c5cc9c943c0a6272aee7a399302ca5f1a26ab2fb4981740f7b38a70e38483e4d447698cf8a7817b2f6d5de09911accced9e69d502584f4789ecf8c282fdd3db6d76874c0daf3eb7ef11bbf1444f57256f }

condition:
	$a0
}

        
