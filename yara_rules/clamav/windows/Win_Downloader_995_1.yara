rule Win_Downloader_995_1
{
strings:
	$a0 = { 02ef9c611e45a23f46f4028195b229909f7455b5c5f8b3d558d4a1cc9beeefe8ce9c840c9c0cd55e780327f10ca0b4ee7b4d0cf8123818a8cd493cedb1680e02102cfdedce51fb001484dd438bb505976afbd5e5e94a148fa3e5e9ec }

condition:
	$a0
}

        
