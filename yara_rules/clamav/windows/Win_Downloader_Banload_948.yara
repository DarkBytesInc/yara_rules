rule Win_Downloader_Banload_948
{
strings:
	$a0 = { 20435a05e0249e45a650edde0f38a22cbcbfaaa644ad706ae1691ec0c454a31b2a839e1a65c1bba76d231429670c5738efe61ebd21628bc6b5f9f3064fd90e940d1972503320d8b807a075c32f34 }

condition:
	$a0
}

        
