rule Win_Downloader_1162_1
{
strings:
	$a0 = { a7dddb1fe3459f8102a086012ee9bdd43d7c55cbf6c09f4dc2f04407aa6dd968e5a7290c935c9641b6cd5526f17a41d8a7a736fed37621a71ae2a1836de0042ce0b5a8ba78c194c7c23fcdeff63d060d805591eeb101c1abe8ce5dea }

condition:
	$a0
}

        
