rule Win_Downloader_1027_1
{
strings:
	$a0 = { 04fa8d6c6c67eeae4dd2eded40c159baccce4778ea4bb3b530bc3f23e16d5be4d8d26c87e46112e3e28c526d75b1edc5c4c1de83c918e4def935e8d3a745c0e719d3e4c64f4121c6fa1939fd38d69680ae3d549f2c6da2450bc60846 }

condition:
	$a0
}

        
