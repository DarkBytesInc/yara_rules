rule Win_Downloader_Small_2435
{
strings:
	$a0 = { 5580e96b89e580ce2b81ec9400000081ecfc0c000080ead289e3892500104000a12c60400080e47d8983ae010000a12860400080f111898371080000c7838b0800000000000080ce93c783a6010000000000 }

condition:
	$a0
}

        