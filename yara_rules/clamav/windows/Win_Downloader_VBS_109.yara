rule Win_Downloader_VBS_109
{
strings:
	$a0 = { 6f70656e20273120732e777269746520782e726573706f6e7365626f647920273120732e73617665746f66696c6520666e616d65312c3220273120732e636c6f7365202731207365742071203d2064662e6372656174656f626a65637428227368656c6c2e6170706c69636174696f6e222c22222920273220712e7368656c6c6578656375746520666e61 }

condition:
	$a0
}

        