rule Win_Trojan_VB_858
{
strings:
	$a0 = { 7ecdf10c2c14b3488790ba6662de07804543e86856238509cb2e0c89c9ad1d57805c3a146c56e57e91220174385967dcd346e59f561b65845a3771df83d6ff381648c816d4dd3d949698c35f39c91507ad0cbc924f1d08a8616e01ba38bad9cd798fb6d5366c33191c61698e1fb36ce232f3c0cbfa843345b4266149920779cc956a7e185d00c1be34c276f4 }

condition:
	$a0
}

        