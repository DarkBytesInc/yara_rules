rule Win_Trojan_Hupigon_388
{
strings:
	$a0 = { 439dc795fc2247806e6472e990fce7df9c0ef8cfc22caf6b6e8656bfb6afdbd50752f33fbf976afc8803d99314cdd8078799fe9f902bc6120f7ae8f8a3c0abca37f53f920117d174dee9d0860e017da091839e3510296741af8d28dd4364ff0314b78512a1162f4e0f53df9f48bc31cf5eeb48c1aaef227009780ef5391e06d432c3 }

condition:
	$a0
}

        