rule Win_Downloader_Small_2995
{
strings:
	$a0 = { 7489bf15fe06c1d17a8226f6a837a60113da83ca32d46e648b9b261fd923bf0e1cdc052cf568832b49b95fa09ed6878d22368c9e7799c0120e4a86461b10d5911826a6723580b44b2665412d61250893efd4a8fc4f0f1ca2db0309e4a7170ba5ba2f899897a9d2d33fdad6de084d8045eb31 }

condition:
	$a0
}

        