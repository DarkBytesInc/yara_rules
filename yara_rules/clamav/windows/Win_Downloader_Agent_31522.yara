rule Win_Downloader_Agent_31522
{
strings:
	$a0 = { 6d376c33db09a8f1854d9a345b92b40bd80276c456145bfe686350530d4081ef1503ff152400c6975067f0ac55591e5750d10ddb8ed199705450276a5c0a9c09e8dcb6b00b4019e8189c234004f61ab82f06451a954fb1c0055c61fe3664484639f3253e88124f19cc68982416a737634f7cb92c0567ec6a1a7fdbfcbe6d21c0ee80c241524f0f1d6890306763dd8293c828063350d4 }

condition:
	$a0
}

        