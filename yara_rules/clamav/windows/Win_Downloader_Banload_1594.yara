rule Win_Downloader_Banload_1594
{
strings:
	$a0 = { 937d0f405455d6f89b99070c38ca68a068985463a9888158a9400dc2189a7f46f923a0a46e4844a42ebca7b4890e3bf2c5e33abb6c9feed7fed6dd4fd2f6eb73fd5a32b790dc1a1d024cb7c8dcc4b0a47237ec5191b23a2a39bf73eebd6f6634cbb2e69dfbe7dc73ff9d7beeb9e7fe41345b8588d06ca9e2f1d58fe583 }

condition:
	$a0
}

        
