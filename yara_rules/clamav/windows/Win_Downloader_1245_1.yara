rule Win_Downloader_1245_1
{
strings:
	$a0 = { c2fdffff8944240480ed348b8562fdffff8944240880c52e8b8516feffff8944240cb64080c2c0e8653800005d89856afcffffe920010000e9fe0000008b8512fdffff89858afcffff80ed2780e60dd1a58afcffff8b8562fdffff8985dcfeffff8b858afcffff0185dcfeffff55 }

condition:
	$a0
}

        
