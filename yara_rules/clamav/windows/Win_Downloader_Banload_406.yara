rule Win_Downloader_Banload_406
{
strings:
	$a0 = { c1cf5865cb89cc3d883c9e7ad69cd6143026522a41be4d8bdaf4ae1682321e76a67ec7269157fbd6c293a17fcc98a1e9eb4c889eeacec7290bca81e77f4a298a69079034d88debc9cd17658553e9cf655f79fbc98cb15e62ca61b7dc403bc7db3faa0144 }

condition:
	$a0
}

        
