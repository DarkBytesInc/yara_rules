rule Win_Downloader_1000_1
{
strings:
	$a0 = { 39de21c2d23d1adec2bdaecec4582e01c404c1ca00c8e77eb6228b03cef7e11a07d06ccb3774b280ce568092b2b21a8236c0c48e8de22fc43b0caa32a0495b4eb6f8aeeace846092e2c2bfea9665e2c64432f199ca16c83648003f89 }

condition:
	$a0
}

        
