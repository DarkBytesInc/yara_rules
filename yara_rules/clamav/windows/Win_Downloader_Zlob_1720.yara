rule Win_Downloader_Zlob_1720
{
strings:
	$a0 = { bebcfbc7ea568054c03e8b6538a4e0b2789775720cfda6dfa7ef07edf882415a0b0dc945b1e9822edfce49acf75446208583d6f5b7ed4cc3204c9e30db7aead4aec4601ba674dfdeba6893bf3bb0525e2d453dd6c4e62fdf1034 }

condition:
	$a0
}

        
