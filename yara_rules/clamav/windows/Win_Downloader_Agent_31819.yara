rule Win_Downloader_Agent_31819
{
strings:
	$a0 = { 94d11f609c3de7fb6a14cf19809b1eb086edbae09c325a45942906fb77f4033354d1c4dd9c9739fbb8f03b5159def8fb74cf1e07bfe66f4bda053efb78cc15d59cc68926b28931fb53c1f451597603d69c73345db7edc1a4990d361db5f0 }

condition:
	$a0
}

        
