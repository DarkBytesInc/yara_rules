rule Win_Downloader_Agent_31716
{
strings:
	$a0 = { ce8d916add9a015889c9797e056a6eceacb40d7cb7e6ff3afa9fc407e4e0f1e20fc820db32a5d1e8b8ea056c06df0f946ddbc9aca912ae4aeb06dda33a2da4149eff1716a265a20a4d3b064de2b53f9a4c852f113fc1c19a2227402b545594a2406a6f965e30475337a3ece10eb4ee10dbb0a9a6f0d4e7cb03ad08 }

condition:
	$a0
}

        
