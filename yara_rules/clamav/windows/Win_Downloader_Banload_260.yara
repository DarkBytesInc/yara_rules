rule Win_Downloader_Banload_260
{
strings:
	$a0 = { 77f68e0ea225375e94efa5cbd6f7df8fbfac329a5378ef9f2f33b9a5e1e072c73466ee1d5b01af59de9cfe6de1c3778347d5201629004d79fc3784b99a48abaa30bef1a7142b77a555c0aa6dba3ca11050d5ebac06a047c03c31 }

condition:
	$a0
}

        
