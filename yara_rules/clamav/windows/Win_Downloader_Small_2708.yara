rule Win_Downloader_Small_2708
{
strings:
	$a0 = { 5b8b40de6a5f656a609f16c5622767c054e06c7f696b4561b1a8574e615876bb9475fadcbd2664c3e56c21ca10902c53e9f5f7300c5675dc658b64ca13e5607dbc250fbf65e3b871879265cd40501c93eea1e034a44226716159c05163e46fdd43a56caebcb5337062b33729a2311d9f56656c4d582530a74cbc32c446b984cc6c2d6ddc55ae339fba0081269fa11e7664626bc4615a }

condition:
	$a0
}

        