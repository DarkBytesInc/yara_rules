rule Win_Downloader_701_1
{
strings:
	$a0 = { 7974f7cbecf61c784ffafe18572d5043f6eb5f641018ff4229e6de9a3f7700684d6a957dcd32cbd52e2d925db66ef2aa62e0d3dcbacb1acc3add23a0c23859501a3438a23efc5dc1d37d6e5eef949e7eb75d512a23cfc8 }

condition:
	$a0
}

        
