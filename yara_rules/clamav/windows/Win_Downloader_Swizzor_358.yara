rule Win_Downloader_Swizzor_358
{
strings:
	$a0 = { 60eb17d71b6c11f1bd4e38865f0d47e84ff24cfcc5c23b18bdebb2410046d52c0d458c941f18d64c27a627f577dfcac88d146193c42e3f42136b4e75347a2db84cacb446767dc1dd8dea03a04efb4aea9dfc974344d7ecd06dcc194a744cfc06b65f33463584205e933a832b8afe10516731e98bf5fff2f43bc5c4b6c48c873b01719de4634953fd8fdbd25e19b893d0af }

condition:
	$a0
}

        