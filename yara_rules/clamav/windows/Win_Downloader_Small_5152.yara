rule Win_Downloader_Small_5152
{
strings:
	$a0 = { be7b3f3757780d828d374673218d5f127be209b7b1a007a5382083c79603b835aaab2072e22433801234da270e09700f25b85412c829ea57d05b16a6d94b19fca5fff433ff8a063ac3433c3d740147563fc1465d8a6d01eb86bd06f51846353b6cd9203a8a52905c091934fa3b3d41381f74427914bbb5f88be85945ff492255348e5dd651e4062e579d980cc562dffe9a5903fd3775 }

condition:
	$a0
}

        