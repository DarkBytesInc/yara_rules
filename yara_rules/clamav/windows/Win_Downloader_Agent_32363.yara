rule Win_Downloader_Agent_32363
{
strings:
	$a0 = { 1b41b67af5a9965536aa032dcb49aa6ac84011a089453da60dc8553a2c9892317fd403dbb256c7d675a245e15fb6bb6c6db6cb60e2e44185dfc1f0577605b766e6e395c2902f45da36a8d9b69c1d78dcde6b8df96daca8d1e0c2f69380cd11f0bbb666e5ddabf2d4db58b574b1591a60db0585b24882da7164494150209d83fe6c5488d91fb8b2e4b18c314611ba448b1123c20f }

condition:
	$a0
}

        