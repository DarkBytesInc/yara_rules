rule Win_Downloader_Swizzor_400
{
strings:
	$a0 = { 89b2870404b0906a87ee3ec99f7fc9c0d59d16ed5218a0976370076c0316700d72b6d50a19ed798d9e57edcf28c2ebf168a06946dcf1d7f0a9bcebd28d71f4f8c5746f7d52e5a49cc6433cd97b2b532dfe1aae374602eddb3991 }

condition:
	$a0
}

        
