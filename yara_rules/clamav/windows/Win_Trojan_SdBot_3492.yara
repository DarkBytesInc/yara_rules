rule Win_Trojan_SdBot_3492
{
strings:
	$a0 = { baa90f28c5f6c87eb3d2a8af6acfd02b022f94a8b34a0f0f9dfbf01a39504dd163f5b1621a98de3bba4856a26cddc011b05f7015673eab458a4d72b8dbf063ca46dd36dd82411c556cd5a55cbaf1dba41c1be32768a1a1c2de68c9c240e68e5921f0fd4f16275a974e29db98beab36f01c6129d5bde4 }

condition:
	$a0
}

        
