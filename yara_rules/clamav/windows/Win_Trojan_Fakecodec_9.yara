rule Win_Trojan_Fakecodec_9
{
strings:
	$a0 = { 6cfeffff77090145b41b8590feffff238528ffffff8b95e8fdffff194db0ff45b8218db8feffff01ca014db4b9c80e0000139524ffffff239580ffffff1155cc0155c029d21155bc4a83fa00721e29c031856cffffff09853cfeffff01458883e85a83fa }

condition:
	$a0
}

        
