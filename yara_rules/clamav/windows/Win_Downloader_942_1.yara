rule Win_Downloader_942_1
{
strings:
	$a0 = { 902cc2961202bcb66ef953044f31d00cccad41260878eaf1b535537b5637c12a24ee105cb16a9fdb5e6835921edbeb8792c9297ad25604f0bc8fcd54ec99a919760c3b0fc6baab9efbe951128d58b2e60fd4bc09b1dd0cf1680f1f9d }

condition:
	$a0
}

        
