rule Win_Trojan_Bancos_1371
{
strings:
	$a0 = { 2d49e9f72d92651b13151de1b70a3d212d217eed897a0dcb66db5987163bbf80f111e4c04a3d7db59eba069a4cc2695ac3301aec42de565363c6e854b0f1741b064bfdac2b025fcff67bef1dc280cc4eefb253269b9911ce2e821faf0cde7f7965eed50722cd5493 }

condition:
	$a0
}

        
