rule Win_Downloader_Delf_870
{
strings:
	$a0 = { 4b216f3b13c2a92d250fdc3eaa1259d53596e8caa58e4786d50a6527e45513099c8c85dec720fd9a981038e9e7aa3c72053fab57fe6a807ef72227e0246823af58fde6d1f0c6d06e2e0e3c539f075d4d0f812fb83b2307bfeccc792557762404af2eb05817e8283f17216adde04d0a88f100f859476a3bec56240abfefd15b21d2b004c6de5bb1a7e74c9eb68f50d3851830d7d8ee }

condition:
	$a0
}

        