rule Win_Trojan_SdBot_3242
{
strings:
	$a0 = { b8a4d510a9e6e7cc5f89d3dabf86dac46ce9bbbfec6d0e6707f949ae643a35f05f6fd51c39e741038c84d111a90906d9914741667a43fdfbd7403630290bc7fd9c2d28f6824a828b08f00020d169483c5f6cb836695b9d5fc97027310c643406e25067cfc962d5a458599727ccc2579e6be1244fbe4a8afc8c627322710e9ef078f2d3b30107f62c534e5c663c010ff57d5fb7d56940 }

condition:
	$a0
}

        