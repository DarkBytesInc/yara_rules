rule Win_Downloader_Agent_35378
{
strings:
	$a0 = { 01000000130f0f30913b3bb2fd4d4dd7ff4f4fd7ff4e4ed6ff4d4dd5ff4c4cd3ff4b4bd1ff4a4ad0ff4949ceff4747ccff4646caff4545c8ff4343c5ff4141c3ff4040c1ff3f3fbfff3d3dbcff3b3bbaff3a3ab8ff3939b5ff3737b3ff3636b1ff3434aeff3232acff3131aaff3030a8ff2e2ea6ff2d2da4ff2c2c }

condition:
	$a0
}

        
