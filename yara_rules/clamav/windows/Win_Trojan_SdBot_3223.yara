rule Win_Trojan_SdBot_3223
{
strings:
	$a0 = { bf0a3df6efcb7f386827db8b546fa1c30d3f5280858784562ce177cd84469156e648594563831ab96d77607e23886874f34affc93c8e4ae86e1c47c773b140af8fec5315faa0df94b39aaa56e6347a84b97c53a2a39a586a91d5df9f38276038b1e993dd6fd861bb4aaa691eddf2057a5f0e481d61 }

condition:
	$a0
}

        