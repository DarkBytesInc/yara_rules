rule Win_Trojan_Mybot_8402
{
strings:
	$a0 = { f4579dd3dbe1b1841ddeca8f9e3c471f5b9acf4049e4c0f06c26a41b56f2eed8788f326aacee9448c99fcf7cfc68d197c662170c314b77672d865f0e89d095531dacbff4245505c8ba554eaa57d69a7b0f0eb38b19 }

condition:
	$a0
}

        
