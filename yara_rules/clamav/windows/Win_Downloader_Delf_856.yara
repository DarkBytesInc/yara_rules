rule Win_Downloader_Delf_856
{
strings:
	$a0 = { b89e3f85bec3b59ef894c61db507d6f01d4fd50430ce6f208a23e40bc7ba53794c5b698e59b61adb75ebb409dfba03e611a714b26a82bde8c297bf5200cb713a3f736cb06cd3d0ba5295896c2ea030ac6c79eaa8b37044380264e582394f4bce6578e1daf488304184107f90e23135ef4578517df56ed6628796f12df3d60fde446eb8be68417ecf575a }

condition:
	$a0
}

        