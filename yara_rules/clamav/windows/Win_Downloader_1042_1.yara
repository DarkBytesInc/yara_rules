rule Win_Downloader_1042_1
{
strings:
	$a0 = { 8ee1fe34345de7d6674728547541a1bfa66b44c9298e2e6788fe6dd5d9206494eeb8d641361cd94a8afec959b6defda4e1e1c944fd45ac296368d47bd2b0f4c5f45e6f0c46f5861d2c50cf6ed7cd80fcb1794f0b2d8a3417ac2cbbf8 }

condition:
	$a0
}

        
