rule Win_Downloader_VB_242
{
strings:
	$a0 = { 6c6f616446696c650000000050555841000000000000000045584543555441 }
	$a1 = { 61007200740061006f002e00730063007200000000001a00000063003a005c00630061007200740061006f002e007300630072 }

condition:
	$a0 and $a1
}

        