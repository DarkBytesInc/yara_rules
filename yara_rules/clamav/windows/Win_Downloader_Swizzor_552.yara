rule Win_Downloader_Swizzor_552
{
strings:
	$a0 = { afbf34d961582df18cc4740e070ae0378ce1897974a9fa8c9207590ae7dc7d7b02629129063ff70a01e953012ec42cd789570b332d0db690a95ebe9587357f6edb5b5e26747bc3690d4eab54 }

condition:
	$a0
}

        
