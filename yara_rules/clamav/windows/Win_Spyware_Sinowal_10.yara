rule Win_Spyware_Sinowal_10
{
strings:
	$a0 = { 9c2652c2fea8bcfcbdecbf385ec29a82a880ed09b73806fa04b096b24b634d2a7c0257b256d65d661916ca538d29cb94226ce9b9f1bb8a609b7537c39b20725c99fce4d1906f48c7b714a9efe43a09de1cead1ea99e563dad9ed9cf71c7af27afa93b56e3ca4638c31fce639c3165316831ed0c554cee06672646a47a584cef10f755435564c072b1aa11af7c6b9535eccd53998ab32 }

condition:
	$a0
}

        