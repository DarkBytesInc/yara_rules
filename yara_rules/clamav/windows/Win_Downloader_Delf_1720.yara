rule Win_Downloader_Delf_1720
{
strings:
	$a0 = { 267802112231201d1a5e74757d7678141400ac30100d4167697766065572068cb0088a9b70bcd6f4f1b79b93831386041f14e877a6186b0c80e3e6a9b1aab8bbbea8dd552b892f0c01ae5b0f96cd8abe0090b362d6b1e3dcc0d5b3019ae0c75526a9e3d69a9194f9f5f59d98002c171f1664e1085e808fdbf3e46ef603c040914c62d01f5a5e6646649a260756565632 }

condition:
	$a0
}

        