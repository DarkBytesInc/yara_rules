rule Win_Downloader_Small_2726
{
strings:
	$a0 = { 276767b8375938393a453727273b3ce8a1e61959c6de659450e89808dc8fa0039d656486c47d2bd95e71b60b71f2176519191b19785923cc4d191919199041a835c877f21cb0fc29fe0b1dc8c8c8c81811f0059191e7c8d8f9e53ced469e23cfa0fce1c0fed50c36b27d46c945b408c0e435c8d8c8c8b77cab0b6426db0bce9f2723 }

condition:
	$a0
}

        