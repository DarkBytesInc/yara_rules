rule Win_Downloader_Swizzor_455
{
strings:
	$a0 = { 135e0370863ae4a2ea8260767d1dd92e23ab4189c320f8818f8565f3629948ae6d119dddcc4e84df3c2f4811ba5d1a98d883ce033ea9ab189a7f8aab63b693a1507cfd17ceca139f00f4def8a2d8afbce1aa62eab907bfd898a7 }

condition:
	$a0
}

        
