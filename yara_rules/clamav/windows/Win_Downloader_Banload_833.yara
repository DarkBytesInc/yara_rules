rule Win_Downloader_Banload_833
{
strings:
	$a0 = { b08117a6e500c80e74f8a55c4f7843667b1f96e046b605af118d9a6f2bc3e629c827c3481beb15b5e24389cc0c76e2c0b91a28230356dc32648b06944f39d18cc3f34f8584dc87614957d1a1ff05970df4154da7f5f119c72525a9bca3047497 }

condition:
	$a0
}

        