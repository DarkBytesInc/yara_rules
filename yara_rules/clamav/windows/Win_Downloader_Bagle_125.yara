rule Win_Downloader_Bagle_125
{
strings:
	$a0 = { 461b97000df5c0b083af6a68e37b077d80dcfa30e6ea0f9513561a3e3d1ee92c6e609ae05a9f215126b4f322a2ca47cbca57f9c2cbf9a4527f237ad315086fbda63bdc45f458fd8c339a5baf69952d0f7081a2d36fb1db1cd8afbd6d5ceec73df98ade5fe5b163a3836c3eb4faa8e5c3af33b729a48cf67b8ed246 }

condition:
	$a0
}

        
