rule Win_Trojan_Mybot_4323
{
strings:
	$a0 = { be3b195e3d672462323cf687ea97750a10d1ab1d7de0604a93d0db31c614d53fe26a6a2eb607e11387dfe49e88b94d995e45db01bf4c61ed93b6ddfb75d5119c3283e2cacbda10a6ad8e9aed85edd018c70a656bf51cf203aee4389da2e63e26c4c283155e15416e4b8f0d171be2bedc748629da1e79153f6ef1002fac1bda38a70e193b0bd0c53d4bd113c18452b0e2d6563c0bc8e3 }

condition:
	$a0
}

        