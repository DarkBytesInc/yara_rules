rule Win_Downloader_936_1
{
strings:
	$a0 = { a78ad817f81bfb6db61954dbc51b2a321ba7256e1b56320f4431a64d8d7a3bc6e53c6ac5354dc53053bf0940985d4bf1a8d5973565eae86cbaceadd5f650c0a6a07a8bf1b8a0148d9d5747c014eeb05d114573bdf1fad40de60e72c1 }

condition:
	$a0
}

        
