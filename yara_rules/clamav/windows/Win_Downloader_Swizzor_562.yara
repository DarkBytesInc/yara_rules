rule Win_Downloader_Swizzor_562
{
strings:
	$a0 = { adffdb873e09b992a9ff3915af92ed05c5ac99af9abdba27c8b4aaf6b1baf574013850821f90a40ca1269fe4d6c8051ff59761e9e56c4ed596d6ac0b4cedb0c1ca54e92a5abee90e3db48dc286c1ecd358af4b65281c4d59a52fc0310a24b6fa15b18c21b8ed6c9d66a8db60b7ad }

condition:
	$a0
}

        
