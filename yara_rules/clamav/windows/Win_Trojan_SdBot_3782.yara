rule Win_Trojan_SdBot_3782
{
strings:
	$a0 = { e86b2047a9f8a3c6a9fd8466b61ceb61dfa15174c2ca321464bbbdddee4fc1137b0ac15572c528adbd9e085027554bd9bb357eefa10416bb02e4fcdf5f75d5bf278e45fd60de58de407057193701fb883fd48b8db43714a466d78093b1f8596edc50 }

condition:
	$a0
}

        
