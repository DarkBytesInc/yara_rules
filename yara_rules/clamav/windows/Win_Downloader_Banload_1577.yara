rule Win_Downloader_Banload_1577
{
strings:
	$a0 = { 937d0f405455d6f89b99070c38ca68a068985463a9888158a9400dc2189a7f46f923a0a46e4844a42ebca7b4890c3bf2c5e33abb6c9feed7fed6dd4fd2f6eb73fd5a323791dc1a1d024cb748ddc4b0a47237ec5191b23a2a39bf73eebd6f18cdb2ac79e7fe39f7dc7fe79e7beeb97f10cd56212c38532a7b72f513b9e0 }

condition:
	$a0
}

        