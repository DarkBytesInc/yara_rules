rule Win_Downloader_Small_993
{
strings:
	$a0 = { 2c7731da553276ba7dd45bdff9857d64d134c11703ef6ad1921fb5938c9f0987fb49bba31b242d272a55a209c072a703e18296b41d3db5227d0a73b391b556cfc024224f5785e16c073d8e1d1de66a34baa63eaf08a1b89ee25aef8c35117805c68ee58161c2ab707cfc42dee74cc6c8777b6009f2db8ed499bf8a1c5211fcaf6a4da811ce995a43831a7850b363a5d80657467506cb }

condition:
	$a0
}

        