rule Win_Trojan_Mybot_6988
{
strings:
	$a0 = { 9d90c0fe0f0294def1f4344eae1ac67cf40972722fd80f2302dc5a7f8f9b456b3e635fced84d144087a8058d38d8f8f88c8eae2ead23b8a0ece127250348c722cb9661cb239bba522a83286e146dd16b2967a17741142c79b36a95caa99d3a74243c57c0d0c6721578a4a0ef0015e7705590398f5ce42f1e4a425bacee587ac7c17095ee68ecc65eae2241aef758dcac014d16cfb5a3 }

condition:
	$a0
}

        