rule Win_Downloader_Small_1930
{
strings:
	$a0 = { e4434e10061683c6dcf66490a62c1e0c75c43b4d6728f8eb1881e277090e001ab12d224cd255436bb32dfa570c22076375c4d1c35c9bf177bdb50fb68401d8d07d8a28848862e037384ac033e10fb70445029672312be7e3a4ce11f39082874704515440a24ac16e2da4e17422d4ea03b45d31e80d6f4858b804e7d9cee60e05120b0811dbdd25e0576a4021bfc06cf3abaa0aa3759b }

condition:
	$a0
}

        