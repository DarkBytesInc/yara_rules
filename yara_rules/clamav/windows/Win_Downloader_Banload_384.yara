rule Win_Downloader_Banload_384
{
strings:
	$a0 = { 8dd5d7524ec63ceccdc4ae480ff9391a68e6765c6915e78f7227c9b1ef799a9c977df567cd25fcae3c7f1f81545c6700595b3079205f400ba6131e8dca4898f2efe037e0fde39e2abfd04ea8630067af719c1650e299b76aacf3e3347ca7c373965d4f96b4213ac3eb }

condition:
	$a0
}

        