rule Win_Downloader_Swizzor_429
{
strings:
	$a0 = { 3f45fa03deb4ddd09d2700130bbc9e83e0cfd314a01d25a18470cb0e2dbde39bf148406bc6961e19ce05bd13046bd1d8098fc3abdab79e10546406e1dc5d886bea7c8be1324005c02f27131a0a9e54dfce732f899b02f68e7446 }

condition:
	$a0
}

        
