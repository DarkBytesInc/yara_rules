rule Win_Trojan_Hupigon_1342
{
strings:
	$a0 = { fbaf785aa635a0d78cc7dd49ea810949499b64b3efdf08a6fc3ac86da89f631a300489070f03ef877873f7fc5391eb737e1f5840e55c00f00e1dc0dded01e852e8df0eec9c4c22c271a8c409bfb1ddcb47c8c52fe2a7801466d0f3ae264b3ffebc45 }

condition:
	$a0
}

        
