rule Win_Downloader_Swizzor_229
{
strings:
	$a0 = { 470c29e92347664e8e6b3c8bbf68db111bee1f47578f98293fb3652077168fddbd2e6d8b994812e1816a04cc2c47f41346b44bb0e8f41243260e852745f3f1615345f0cd54f46bcb8be864b522bb4a045b31314ac6daf8863e80a149cec635a142588e33a6546630957951e7cb000350b62ac700006a9bf7c70abda02876b9913ce5cf3dfd1d9a42a9d74d0708b4de54f9f81861451b }

condition:
	$a0
}

        