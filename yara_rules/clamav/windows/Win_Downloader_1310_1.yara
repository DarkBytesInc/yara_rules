rule Win_Downloader_1310_1
{
strings:
	$a0 = { f8704063772d0c92ff87521b31c490364f7cef2d732a8d5f100aa9ffadc21ca9da06f4bca8221642fdc1fde4c3fd6b9c7091a922ac6579ae9ff3a3e80be728bc4f00dd48ab199cb895b28c4d1a4fcb7c8e0d2e646974f18dd390d0e56b8b5953d6da7fc07450 }

condition:
	$a0
}

        
