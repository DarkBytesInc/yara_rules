rule Win_Downloader_Zlob_1862
{
strings:
	$a0 = { eca40000008b1dd7484000c683640900003280e290c6835f09000072c6836109000065c683650900002ec6835e09000065c683620900006cc6836909000000c683600900006ec6835d0900006b80e176c683630900003380f29680f2f2c683680900006cc6836609000064c683670900006c80e14183ec0480ec298dbb5d090000893c2480e6a4ff938a0300008983600700008b8360 }

condition:
	$a0
}

        