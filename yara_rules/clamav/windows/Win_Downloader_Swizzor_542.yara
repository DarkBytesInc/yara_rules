rule Win_Downloader_Swizzor_542
{
strings:
	$a0 = { 86a73f6854c0605ef9c9b5ff34f007958d9414f933f933ad92caac840a39bf9b733ed6d48af6c7cc36926c0a5aa88e525e435dd703c2a859de746b9e7e99d33a5a90755b747f83ff556e77086e725c23a008dbd7ab6c8396f6301569a98cb299c4846ccb94a5981a239ed2eec241f0455898ca5ddd70ca9a }

condition:
	$a0
}

        