rule Win_Downloader_Agent_32761
{
strings:
	$a0 = { 0889042480f50a8dbdf8feffff897c240480e6df8b45088b0083c07880e1b8ff105d80c222898500ffffffb10983bd00ffffff007402eb0c80e22883bdf8feffff007505e9fd0100005580ed7283ec148d3df0a10110893c24c74424040000000080e162c74424080100000080ea3580c11d8d3db6a00110897c240c80ea718dbdf0feffff897c2410ff1576a001105d80e92d89 }

condition:
	$a0
}

        