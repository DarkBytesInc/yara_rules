rule Win_Downloader_Swizzor_456
{
strings:
	$a0 = { ddfaf463b126804a5d47956c2332c4fcb45a79c6c2956c20f7846d8d2d26ab84b3f8a3d055a0a5be3bdaf8a04931f9ad75b9aff15ea9b7af7556e37f6dcad06c891208b0153be8bd582504bb72346ffe0653453472225dcb5ec6 }

condition:
	$a0
}

        
