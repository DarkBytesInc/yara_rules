rule Win_Downloader_Delf_926
{
strings:
	$a0 = { 9738882e7a4a1df946ad232aa770a62bbd082bb1f365557509e91bae34e985051f96efe93026b33d1a8c5cd6f4f1b115e9fa6e82dabaca33e8d7d62d00ed1c12c7f9e5e4a259a0b51f0ad798cd423853d9ef5023b9bbfb6be8418638adf3809b0d608e36 }

condition:
	$a0
}

        
