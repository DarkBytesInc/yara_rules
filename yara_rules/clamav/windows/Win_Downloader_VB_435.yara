rule Win_Downloader_VB_435
{
strings:
	$a0 = { 64002000200020002000200020002000200020002000200020002000200020002000200020002000200020002000200020002000200020002000200020002000200020002000200020002000200020002000000000000c00000020006f002000200020002000000000000a0000002000200077002000200000002a0000002000200020002000200020002000200020002000200073 }

condition:
	$a0
}

        