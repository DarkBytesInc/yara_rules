rule Win_Downloader_1263_1
{
strings:
	$a0 = { feffff894598b1e331c031d280f5a380c19f31c9b9020000008b4598f7f18945988b4598898574ffffff80e60380e11c837da8037402eb148dbd7afeffff83c7088b0789850efeffff80e97a8dbd7afeffff8b07018574ffffff8dbd7afeffff83c70480cddc8b07018514ffffff }

condition:
	$a0
}

        
