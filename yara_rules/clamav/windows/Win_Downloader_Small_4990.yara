rule Win_Downloader_Small_4990
{
strings:
	$a0 = { 48fe322da40c8a3291a4248631c1d608928654e518ae86540930ba8654b124b686ac80213ceac6c819901cfd01ccf9116b03d01569b507444dc2a104d4380085bd24303f03782ba0e49b4889dce73c2953163ea8e27050ec18f703dee04d784b2db5c905 }

condition:
	$a0
}

        