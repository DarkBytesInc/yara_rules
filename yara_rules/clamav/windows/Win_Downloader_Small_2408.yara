rule Win_Downloader_Small_2408
{
strings:
	$a0 = { 0a5589e5044f81ec9400000081ecfc0c000080c6bf89e32cf489252b1e4000a14860400080f54989837c070000a14c6040002c61898340070000c7436600000000c7836c0c00000000000080e23fc783a701 }

condition:
	$a0
}

        