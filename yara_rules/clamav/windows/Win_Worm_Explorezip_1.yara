rule Win_Worm_Explorezip_1
{
strings:
	$a0 = { 32c4c6067c183410b752453a0fd1bff9060b107a69707065645f668041bf00bb732e657865f7f68c7dc92048692017022123e126835c40041952b98c54b30c5369a7209799f86c79200d46332e5897ec3d6279650e0fa7202b33c8801d0a0b0d3800d86e6d4920585c6976bb20b6f6ae370c722065a26c20616e0e19737b05dab69e6c0b73f11b1468b2775d2a708441534150 }

condition:
	$a0
}

        