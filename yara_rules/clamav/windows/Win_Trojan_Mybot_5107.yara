rule Win_Trojan_Mybot_5107
{
strings:
	$a0 = { 9a7822ed216a4006d9f4bf80b6dbad7de8a55850f4f3abaab4fe845a35058289eff118ee9afbbb3fb74def1501c2fdb10a0b5e41a9ff86be3bc20f8793f82588827e7d40ebeecb521004b8b6345285514411b87caa8dd727840826b7fdcb742c8a51014ddd25131c3602fa05678277a10540bbd292e8b2b7089046d1405b37f5d04141126fa994805c1b091578fc047235 }

condition:
	$a0
}

        