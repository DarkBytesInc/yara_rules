rule Win_Downloader_4433_1
{
strings:
	$a0 = { 506a00e816c7ffff8d45e0b9588040008b15a8a84000e813b9ffff8b45e0508d45dcb9488040008b15a8a84000e8fcb8ffff8b45dc5ae873d5ffff6a008d45d8b9588040008b15a8a84000e8deb8ffff8b45d8e8d6b9ffff50e8e0c5ffff }

condition:
	$a0
}

        
