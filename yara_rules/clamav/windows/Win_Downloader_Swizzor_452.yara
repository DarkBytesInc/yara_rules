rule Win_Downloader_Swizzor_452
{
strings:
	$a0 = { aaf1709eab4b7dec75a79e738e30fcdcc7bbf26ce38b54e6417046aa7d79a8027a48cc5d48a219c0bec18cae56045214fb9d64f5bcf838fff8d029ced760cbb830b9c3686b07e9703bfa7dd1cf464bde5dd9fdf40c17caba973c }

condition:
	$a0
}

        
