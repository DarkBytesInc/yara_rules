rule Win_Trojan_Bancos_760
{
strings:
	$a0 = { 52365d2463e6187d2c2d2ad6e8a046f8a5a4e6c57622a5c7c592505ddc9c5b679a65acbbb29a683254d9fc6fb2e7063b26876e3264ce7ffb0635b4d5f48adff344c852bbeacdcf60c309d1cd97f49d04addc3cb0bddff4b683dbf3891aaa07b3bfe862e46a0d0ff5396e49a1042e }

condition:
	$a0
}

        
