rule Win_Downloader_Small_3182
{
strings:
	$a0 = { 1ec6345f3298207cd11200dbd06726c2ceb2715db0663d253758e051d192f69fea9b60851198719a276a73d02eaa77c82498566552ffbe582c6b77d23d8a55c05e1796c96a75 }

condition:
	$a0
}

        