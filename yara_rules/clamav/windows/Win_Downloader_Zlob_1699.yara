rule Win_Downloader_Zlob_1699
{
strings:
	$a0 = { 9c2078bbfbd9b8a499f6ffced00d316535ad0d7aeff2108e48d5a62ec2c9041dd8a6f25d3ef4ee9f2cbc36465cad7f0bd7c3412ab1ceb2f1166b706674a3cf4c6e9d50e5746fa6c1a181477969f3737316915fdd8b11f54110c2 }

condition:
	$a0
}

        
