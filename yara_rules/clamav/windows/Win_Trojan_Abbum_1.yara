rule Win_Trojan_Abbum_1
{
strings:
	$a0 = { 54787446696c654f626a2e57726974654c696e6520223b497427732061206261642064617920706c656173653a20414242554d4d415449212022 }

condition:
	$a0
}

        