rule Win_Downloader_Banload_374
{
strings:
	$a0 = { f8a3545a9a7c8964acb60de614eff6d0f151e6ed3e6dffe603a37e8b3e6e544b33cabe2b2822fd30e8e436ea091c87087dd1db75529a537e0a9663bbe0f39959fdcdddff2d0fb1eb5406ebff9d30848f1b96b6871d5f65a622007571ffe9974aaeacc5f9 }

condition:
	$a0
}

        
