rule Win_Trojan_Hupigon_767
{
strings:
	$a0 = { a9fddf14cee40443ea614e33b08038994763957484dd644ae792c1b55cad15454d0385b8e6018d83c90ec904041e27343fa29a72c2074cbb0e37fe13ca3274ec8b0e4e00b69a71df1cd44eb74c2a1f02f2f4957e2bd318312a5ea43a110dd1dce9313cef11f6af8777ebb98efef785f2693ec3d02b7fe2dcfaffb80d49f6bb067b3419a312dc033a2599e8f6 }

condition:
	$a0
}

        