rule Win_Downloader_11769_1
{
strings:
	$a0 = { 536a008d85a0fdffffe816eaffff8d85a0fdffff508d959cfdffffb884744500e8ebe7ffff8b959cfdffff58e82fecfaff8b85a0fdffffe81ceefaff508d9598fdffff8b45fc8b80f8020000e88fd5fdff8b8598fdffffe8fcedfaff506a00e8b80cfdff }

condition:
	$a0
}

        
