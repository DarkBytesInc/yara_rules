rule Win_Trojan_DNSChanger_129
{
strings:
	$a0 = { 4e4d45dd5b0095e9020e1079d2c0a9161e6dbed6607e20b0da43f99f5b8503751c8c559d60460c92df4d559d5bd506f5a48a4a9da490918d1b856e5ed2c0a992df1c559d5bbc088d2e9d06f75fd6aaa81794159d08d6aae8a7 }

condition:
	$a0
}

        
