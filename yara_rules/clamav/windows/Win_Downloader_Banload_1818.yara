rule Win_Downloader_Banload_1818
{
strings:
	$a0 = { 9f36fff2af46fff9cb6cfffddf90fffff0a9ffc79e60ffad8e6fffe7c8aafffee1c2ffffe2c5ffffe2c5ffffe2c5ffffe3c5ffffe2c5ffffe2c6ffffe2c6ffffe2c5ffffcdadff90615fff0000008f0000002f0000000082591a05dba034d5f7ba3dfff8bc3bfff3b2 }

condition:
	$a0
}

        
