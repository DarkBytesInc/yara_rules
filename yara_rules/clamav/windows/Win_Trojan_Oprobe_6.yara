rule Win_Trojan_Oprobe_6
{
strings:
	$a0 = { 5c007e024efbe93f00be378e7f012e3e3a9a169fd1fb7e05bd363cd1fbe92400bbce35e909007000bd45f7fd2bdfc3720b3ab8008eb34cf8e8edff3e46d1e245e8e5ffc3c3e8e0ffd1ed3e3b73ade8d300b37ae81a00ba13ab7a03e8c5ff780bb36d23ec7805d1eeba183df9e94b }

condition:
	$a0
}

        
