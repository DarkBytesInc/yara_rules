rule Win_Downloader_Zlob_1394
{
strings:
	$a0 = { c1e4aa350c324fb714729bf0aa0d0ed70d403b4c473f7325211514db3d70ab2fd2e8447e2b3e88e29f790d9b85d69ae637ae7adc01dd01cbe9c0ab65054e413228a96f34d190be4abc1acdc7ca885c6ca7f9160a09bafd99a4f1aa834d35b29f7a63fed6674845f4c52a71f54c888b78d8aa2d538f15506b10b55d1b803f937d619f66b024f540f88d1eb96306d3ed73 }

condition:
	$a0
}

        