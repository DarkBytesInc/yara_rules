rule Win_Downloader_1097_1
{
strings:
	$a0 = { 74522c8045541dc458406da4108cf870671f22ac60eb0f5f481af2b9fd00eaba5c68ff68ff26ac90a9df8a62acd00bc87ce61b98dc36a0085d0cbc0f2aff48d0a283f17baef3e4b67dd4acda94481bd940780a350ad70c6f2b99dbb6 }

condition:
	$a0
}

        
