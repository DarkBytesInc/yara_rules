rule Win_Downloader_Dadobra_223
{
strings:
	$a0 = { 706ba4d60dfe95ddd17f9e600f2402dd402be548b3eb8d9b3dd6ad9656159446fd7d032166b4e400b790b948ce2d3d7b349c89931de06f3edd5f75585d7acbdf6b81967f05d9a5f348eec69c9447fc3870c47efc511fe2b6bb4e }

condition:
	$a0
}

        
