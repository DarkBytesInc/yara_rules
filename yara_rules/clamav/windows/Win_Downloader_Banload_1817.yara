rule Win_Downloader_Banload_1817
{
strings:
	$a0 = { 0000c3a04e4ad0a65c5400000000c3943509e2b747f9f8c84bfff6c442fff2b937ffeeaf30ffeba92affe8a629ffe6a329ffe59e28ffe49a28ffe49b29ffe69b2affe69a2bffe7992cffe7992cffe7982dffe7982dffe6952dffe6962effe8952effe9952effea9531 }

condition:
	$a0
}

        
