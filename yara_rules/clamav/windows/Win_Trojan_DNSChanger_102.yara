rule Win_Trojan_DNSChanger_102
{
strings:
	$a0 = { 4505b3f5cb047906eb446369500d627f4616a36addcac1339e5aee562c56eeb7e23735a5a45b72ee7f05636a135a6f795ea1636ada8fa4a65d816bdeea91a772f213eff4da0463a32a6972ee5b05636a6575c3f51f112452eb0754d05fc5d873e9bba876054b73552e90a9822d90c18e3190e18adddd666316c7ecafd28eb8665932ee71ddc5d7815a3d }

condition:
	$a0
}

        