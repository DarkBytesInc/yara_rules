rule Win_Downloader_Swizzor_447
{
strings:
	$a0 = { 071bbf5fef04bbb2be59b07f0ba53415b06cfccce0f443bbf5f1c2f93f7aa55e54d1e04e76af3d67a58a910ce6b50e4bd7c723c7bb777d9c9ecb52d6d5380930dda874f60b651f57d10050c7877eb171f03e09efe9aae42f9201 }

condition:
	$a0
}

        
