rule Win_Trojan_SexTest_1
{
strings:
	$a0 = { 642044656d6f6e076563686f206f6b0c64656c747265652f7920633a25202092a5e1e220a2a0e8a5a920e1a5aae1e3a0abecadaea920ada0aaabaeadadaee1e2a8212a20202084a0adada0ef20afe0aea3e0a0acaca020afe0a5a4e1e2a0a2abefa5e220a8a720e1a5a1ef2c }

condition:
	$a0
}

        
