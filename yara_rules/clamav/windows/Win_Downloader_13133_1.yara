rule Win_Downloader_13133_1
{
strings:
	$a0 = { 4c6f6174641d696272b92f794b87824bf6a8c9c5e0aaa225e3d366eb21dbd52814ffc69008cbd59eec7036e28bb2027ee85b2960ab3891a3c89be4933708c2fee114b71458b7305c884d69fb927443c28c621416e8a1e9f359160f8ee421bf9eda4b8a56961c7ca219c6ba9c57b1884e6ac827e2ce87318a095e6c4f61a30673583088fb8129224c4f4b49 }

condition:
	$a0
}

        