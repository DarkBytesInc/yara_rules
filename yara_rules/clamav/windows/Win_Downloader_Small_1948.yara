rule Win_Downloader_Small_1948
{
strings:
	$a0 = { 833b0c00006e80ce76c6833a0c00006580ee64c683440c000041c683390c000053c6833e0c00006580c158c6833c0c000064c683450c00000080cd4db55f83ec088b4366890424b5aa80ed2c8dbb350c0000897c240480ee21b501ff93db00000089838b0c00008b838b0c0000898325080000c6832e0900006e80c5da80eaf8c683300900006f80e66ab2e4c6832c09000079c683 }

condition:
	$a0
}

        