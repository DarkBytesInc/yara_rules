rule Win_Downloader_Zlob_1439
{
strings:
	$a0 = { 096a792849632aa3d99e330776f4a0f1de7ae86bc3a93c7f005cee69c9652f439eb86137a055201d59bd744887ae9999cd7792c984e97fb8aea88bd6f1f1077ae3757a4b361146b09afe586675a9afd8a78e6288bc8e12d578964e870904f4033eb5727079669691cad2cf366ca53a91ae717c8a79c41c32449031e57225225b7e4f3fe8556ee6 }

condition:
	$a0
}

        