rule Win_Trojan_Bifrose_459
{
strings:
	$a0 = { 3da7baa9c74dd947fd8b26fb66c838f8eb0d15673fcd46f7bd117eeed518d12d95c44ae0290e2682fbfd654eab8017f3edebc667993b05c5603893eeb081724954ebe2fb9720071adb824d8baf83214b642ef52527987d246ab1542daacd92c0783403701c7806f30f4d95c249c8dc7191e926a6ccdfd6e4eb32729f462ca5be8dc91cd76a72ed6bad119c1a }

condition:
	$a0
}

        