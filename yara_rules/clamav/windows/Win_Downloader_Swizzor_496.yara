rule Win_Downloader_Swizzor_496
{
strings:
	$a0 = { 4e9423a5f324fb839212caf326cf515abdee16f00c8ca4397f641bced6af90dca8214a8f3412b0a701df2f118b9dc4ed132471fdebe1a2c95e581a7c1515407c2cefc98d4ebeb28ec3fb62febfc2419bbdec88ded456b06ad432a741606bd92a245d2ff796dae84a43 }

condition:
	$a0
}

        
