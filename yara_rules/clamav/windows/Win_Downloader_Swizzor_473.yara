rule Win_Downloader_Swizzor_473
{
strings:
	$a0 = { 0cfb8679f0e066b8d3cf59ea5b1b1349577b1777836325e29dea3accd78559a0a948a0b5fcdc4d71b3f55606dd5b82257ae5488e86fcc5c0740568c9f9e2dbfe6fbfbba2a5d77eed7c6f7db3a67e64273fd04f0e130eec9e4b3f }

condition:
	$a0
}

        
