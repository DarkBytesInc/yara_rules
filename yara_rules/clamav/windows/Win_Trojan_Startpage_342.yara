rule Win_Trojan_Startpage_342
{
strings:
	$a0 = { 244000b8e0144000ffd0ffe00000000c00080000000000000000000800000048004b004c004d00000000000a00000070006f007000650072000000294fad339966cf11b70c00aa0060d39306000000730069006c0000000a000000730069006c00 }

condition:
	$a0
}

        