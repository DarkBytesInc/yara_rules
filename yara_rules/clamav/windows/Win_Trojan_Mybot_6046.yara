rule Win_Trojan_Mybot_6046
{
strings:
	$a0 = { 6fb1afc94bca9bb342a5a41e483a20763bd0ae9afaea9bf8fd87fcca24391e6dccef0f5247a3e5e3741fe6e4cfb5b6643712a00217fd23a51f8085d8a84d0f91731881c35f93ca941b3bc8b79b962ecef17d911784854c3dfe6b22a41749760cfa912b6a74073e7d93a6cef031d14ba837df194bd4eb }

condition:
	$a0
}

        