rule Win_Trojan_Small_3732
{
strings:
	$a0 = { f24f95cf6e63bdc9c5f57dccd77390b96fe064eb728b7cfc33a47bee93a37b8f779bbc79cee9d9d4c84ed3d0d78b8c796ff5847884c38cb96fdb7b8fab9bbc79fa7be779d9aed2e36f8a92cd7fcb7cfe2f00af04acbb8cb96fe17b51f44bf19ec58a54faebbb7bd6e493d278460ce1a96e8ce4 }

condition:
	$a0
}

        
