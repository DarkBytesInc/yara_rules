rule Win_Trojan_SdBot_2423
{
strings:
	$a0 = { 5641abf25168b72d8a5a15b54ad5aae8de9aaa45ba102034eff99f997b937ee8fa3ceffbf2fbd1dc39f33d7366e6cc99f331d5dfbaac75732f8321e09d763c1229c83c68578c4683c157148e0c6cde6b3378abdcbd33ab5a3e2398c3e9eae532bae22203d56a9bc11f2a7b2f92d36129 }

condition:
	$a0
}

        
