rule Html_Phishing_Auction_254
{
strings:
	$a0 = { 61797374617469632e636f6d2f61772f706963732f656d61696c2f6d6573736167652f62746e726573706f6e646e6f772e6769662220616c743d22726573706f6e64206e6f77223e3c2f7370616e3e3c2f613e3c2f703e3c2f74643e3c2f74723e3c2f7461626c653e3c7020636c6173733d6d736f6e6f726d616c3e3c6f3a703e3c2f6f3a703e3c2f }

condition:
	$a0
}

        