rule Win_Trojan_SdBot_1171
{
strings:
	$a0 = { 8b9f568c5403b0accb23fdb1b758dd8f2c159265a1987832c14ba7a6c9bddf495e169e66762a8ecdc6498d1eb2076e65703409d2083d2495a217027597d4c23881c81017e8b37ef00b8bbb94d7a627a4401f9314e639929228c08489743cb47370588826f0f2f4798614f5b98b9e87460e94ccd4764f76ee89b9da29d0811cff21bf71fe7b4cfa6f71827faef185399a0e735b13af8b }

condition:
	$a0
}

        