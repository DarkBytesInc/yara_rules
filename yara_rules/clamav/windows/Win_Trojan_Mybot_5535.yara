rule Win_Trojan_Mybot_5535
{
strings:
	$a0 = { 936b7633667decfa145ce85b85d231843aa0a102d7bb0816b7c4000a61046c6979a20fa18cfec0b5e6c10489693214e94d7efdd34499eb3afea3d90f3c4621931da90e340508addd92e2384a56e330594659376942a13af15634f30a6080de792611b761e487a7d71ad5bf530ad9394abee5dd462330b8b0fe7622721a420cb706947c4fe3cf3bdba34de694144669b76446de6ac695 }

condition:
	$a0
}

        