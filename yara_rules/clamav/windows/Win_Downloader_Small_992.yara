rule Win_Downloader_Small_992
{
strings:
	$a0 = { 417fde7aa4fc9479e6a8d8290dd35808d372690f9f36d531ef7a4cecd27e4d694d6eb06a35d4d37580e3ff14f2f724e942d4f7326f8fc16af4f768784e391fcb0a3a707e1ded4da26d5d647ce3f8d21dee4c3e56bd2a2ae4d0cdf563b91a6bbe3bf54d30348f573f85c2078f0f075a0f226fec16237f1aac09ba03cdbf6eba4846ecef5353019851495849c5e7517b17f901a4efd18e }

condition:
	$a0
}

        