rule Win_Downloader_Zlob_2152
{
strings:
	$a0 = { 66667b6c9009f36fa7a22d57af7e1efa59dc62f56dc1c1d44787a423dbdf7f9ab97c2badeba6594b89e7ab77045ade2d7b3fa1e195bc8e2b74c7737d06a50cf1ea3647b7a0e9e9eb278a8a7803eed8b34d6fd2232f6c78bdb555e6bdb1b7b68b66d2c5673f04b7343d1b3fb2f464935d }

condition:
	$a0
}

        
