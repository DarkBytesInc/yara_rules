rule Win_Downloader_Swizzor_598
{
strings:
	$a0 = { 84375b1de19cdaccbce18df2f3e80f06bb4e6cdff35474322ef2b58fa4699d6da47437e29db7ccf9c2a46ecf7d7d94ba63c2b640858e563d98c8686b63cab9a7c6ccc7ce130f93210e901a1a95a28dd41007dfbd822fa144b9c4ac216e062f19c902b704f08bcd780c }

condition:
	$a0
}

        
