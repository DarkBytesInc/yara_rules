rule Win_Downloader_Swizzor_396
{
strings:
	$a0 = { fcbcbd806e9518a87f19c101af092c2c7a65f1c9fd6b59cbf50bc47288b0a6c0d127ce2eb502e08ddc6e8e0cc174e519786486ee21dc6f2da2902db441355366ff08a3cf5214f761dda841abd43c8117c5462272f7e67a7cc40d }

condition:
	$a0
}

        
