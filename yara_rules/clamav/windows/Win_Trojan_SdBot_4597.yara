rule Win_Trojan_SdBot_4597
{
strings:
	$a0 = { fe0ccb045cd40eba0dd24ad3eef546798c7c0f90e0838aee9ec145300aa41f95b72541e10472f3b4085e08e7ce5b2e0bee8958e0f67f87d51c722884ef43e3b373336f411e892226b06172cda5cc80f3fe3b7f0b14d7f8e89a6516963c7018411d9a06f59f2bbe7419fd3e82f730284500d9805773ddbf83a819a118b65ccd81211fb5901ca4a5c43bdd2141 }

condition:
	$a0
}

        