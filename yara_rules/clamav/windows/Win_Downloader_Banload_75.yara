rule Win_Downloader_Banload_75
{
strings:
	$a0 = { 5aa55051c3d24a0fff8fdf7ca8e64e26b525853fc0ca90432f18915c9c56d8990a1d586f396a4113048124421b0347032d65e2e7c21134577b36024fb0b76f7e0043f004a8c4dfc22b98e1bc29c0a6ead536f6899171d854a7baae0c19a0192a63bc89e7f6c45fe4c17bc992c64a6e49cc2bfc0d6202e294 }

condition:
	$a0
}

        