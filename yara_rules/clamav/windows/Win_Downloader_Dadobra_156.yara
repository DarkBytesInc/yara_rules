rule Win_Downloader_Dadobra_156
{
strings:
	$a0 = { 3f461e8da18a9faa9e86e5e2384d52fd7b735e4d2ce95cb03b449830c3c5c11e85e56c291cd5cb8d3190ce0f8a9632547f28ef7dc5fa379adc120fe9448045660ea1dd2e51af5f13e92efba7c96dc0dd4b702f78f02dc0cf133c3e91fc39f2e3c3dfc709 }

condition:
	$a0
}

        
