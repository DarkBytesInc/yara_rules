rule Win_Downloader_Small_307
{
strings:
	$a0 = { ffbfe7180e03ba1720b30effa5b14d2c986d21ff17fa5f3c564e6a720b0ba737854f59c84c72c8d74bbc580bffffffffa81cee649b29acaac2193334e9d97bf86e90556e74307243644df0515669ccac8dff7feb702320227dccdc10fb113a7e3bfb0f8ead2c8bb8fe0bfdad2e5650a575dd0eb2ece66618f8532fe4117f }

condition:
	$a0
}

        
