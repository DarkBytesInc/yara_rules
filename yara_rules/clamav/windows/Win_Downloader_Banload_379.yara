rule Win_Downloader_Banload_379
{
strings:
	$a0 = { a037bf7e26e9529bfebbcb8d051dc3effe83fd679dbf164c3a5a610074e25d275ffaa3fc2ad5179d99f67d58f359ab474519dfce1a1ef2f7959677ab752830cd3e80ba5d02b6fb6c29a2296ba5208e637d2d1047a208b8468eb7a66f9f23a0895465f5e4e1a5c17cee }

condition:
	$a0
}

        
