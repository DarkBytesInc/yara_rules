rule Win_Trojan_Small_5348
{
strings:
	$a0 = { f689cae8e98d76f4e2368d6efb7677072f2b05c4e68a02b49a48b77e3ac4bc723a9f8a7eea5676f4e2febc7aee36777ee90db1dbdeab99ff672b407fea36eb976bb46b13eb36778d6e657a7eeafdbc6eeb36777ed3597a7eeac3bc7a3d87cae821c0d47ae9ac6f7ec070 }

condition:
	$a0
}

        
