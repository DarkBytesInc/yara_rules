rule Win_Downloader_Small_3008
{
strings:
	$a0 = { 188681ebe3d9935a57389cdd2adccffbd7a72489fbec7306cc1914030f0ff8378f5ab362c13362d42acefa64fe7d8923e9d5cffeb0c7a568c7d2199a1b59ceced46875d2c83a276ed615c74ac2bf4b0d91dce8a55d8b4bfc99b27674f21453484c6abb0fa615a1cf585b8b034d1df7178666 }

condition:
	$a0
}

        
