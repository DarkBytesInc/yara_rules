rule Win_Downloader_Small_2988
{
strings:
	$a0 = { 7ab1d310a821627e662900b775a7574b4a4d2fc274ffe0738fae8bf50f914d8117c911149c47facffc3d33e11074d6a875e3786e7673e8a9aa1abdc82f7068c7676854f4fe1f5a867e1e38cf201977863b2a13ee4f13050cf16084b9fbcbc46a2ec3d9cdd7faf8c1fcb284d56470339b7cc6 }

condition:
	$a0
}

        