rule Win_Trojan_Lmir_208
{
strings:
	$a0 = { 950d6c35096374aa23ccab8ec45876e6f4d22ffb90d3498c41987c2dd786c55c09806b7f58f33395cd130a3ee378019e64589457d0556198a2591dd839d24da0989c607ada74219804931fb2910951591c2f9d4b8efb231c70a49b4cc8ef67d7b2dfcf1ef4a9aa10c693a10e4a5a01681ca1b7512ab81eeb3e2678ec2a92798fe3a5091a75f056acf7fcc1518f7d92b03b41fdabc00b }

condition:
	$a0
}

        