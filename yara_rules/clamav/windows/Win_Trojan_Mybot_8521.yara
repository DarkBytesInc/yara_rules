rule Win_Trojan_Mybot_8521
{
strings:
	$a0 = { 35408306c80392b8f0bdb566ccb72e37240cfc821487aaed80d695b81e24f3ed053e902f0468d3bac79f816e6623b29465d7bcac3684836a5025b4a0da6ed0110fa65f7a381f62434b1e40dcf5fea559be64894eeb6fa7c80658f212c7161e47a8c7045e16b310e67e581ead1125e2a2e929352ae522018ae4759f49f0bb86c423aa0c469e169f691b8af7a0 }

condition:
	$a0
}

        