rule Win_Dropper_Small_248
{
strings:
	$a0 = { 3ee8fa16f62f3d0aafd08136e92d03582189335df0a68038293d30909c590f8d50a53c4529f4504086e8e120779c5e26db15f0ee693bacf03ce825fc21397e7724d3886c5d542ef01ae8ed095b0e826674622a62ec243560f28656d8152f4d86253b30f1d80f8729ae05a261 }

condition:
	$a0
}

        