rule Win_Downloader_1155_1
{
strings:
	$a0 = { 2126b1715a25dbb11883f327cce571092401bd0f22ab281a275bb4a088db7a2923e476b6783abe2b89f2ff14a8110dbb9dc0215b2c69de6f23ce6c1e52b43aa519f0fcf0fc844fd1b30c26a0ddfa173652d441dbdcf73bf1073f68e4 }

condition:
	$a0
}

        
