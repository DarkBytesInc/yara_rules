rule Win_Trojan_Hupigon_325
{
strings:
	$a0 = { 88bdc6bddf013f6412256510975eb5afe171e24158848f0946cbd67f5555c4925a5f357280c4520a43bc585ad4f814e0e1076ea8f9d414b8ea84fd8e03a5265e4ffc91638ab369155deda38cfb49b3bb4eae0a41ebe7d2a1833f }

condition:
	$a0
}

        
