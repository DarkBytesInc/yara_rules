rule Win_Trojan_Otran_1
{
strings:
	$a0 = { 5d000000040000002c00300000000000020000005b000000020000003d0000001600000004000000010000000000000000007301ffffffff010000001800000001009200020000000000000000000000000100000000000002000000780000000c00000053006500630072006500740000000000080000005300650078007900000000000800000050006f0072006e000000000012000000500061007300730077006f0072006400730000000c000e000000000000000000564241362e444c4c000000005f5f7662615265634465737472756374000000005f5f766261554931566172005f5f76626156617232566563000000005f5f766261566172416e64005f5f7662615661724e6f74005f5f7662615075744f776e65723300005f5f766261566172496e6465784c6f61640000005f5f7662614765744f776e6572340000000000005f5f7662615661724d756c005f5f766261566172416464005f5f766261493256617200005f5f7662 }

condition:
	$a0
}

        