rule Win_Downloader_Zlob_1444
{
strings:
	$a0 = { 8e987b8d0f735feeb459b1d841dab4ca5cf3828374f69b7f02f6de4277752eac9f3e26b2c5b27bf60e8978c3d8f2194bfd4932aa4a41360346305d40beabfa4ff63dbaabfe29379e22d7349e34ccbd7cbb738c846aad8faede9554e311b6c53620e18b5b2e8b554b }

condition:
	$a0
}

        
