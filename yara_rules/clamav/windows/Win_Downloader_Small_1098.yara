rule Win_Downloader_Small_1098
{
strings:
	$a0 = { 35657244b6738820432db69d29770f8837551102b52c54cf3548c04c9604d09556b5a712cc8ce833aaeb3a9f6857e5d610a302701ca0890ee8f60441b59ef97a61754de73f3d6f55426f5dd6aae10f77b9d4748613a7a0f81966fe275adeb55deff8030b6e6082329ac9009758dd3c548bdc95695c2abe1bedb415ad9d0c53d4c6c74122671d2464b0ccd65ade95724a52b3144b5631 }

condition:
	$a0
}

        