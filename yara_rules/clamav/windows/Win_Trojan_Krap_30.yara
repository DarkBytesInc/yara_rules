rule Win_Trojan_Krap_30
{
strings:
	$a0 = { b8518bd9a6ba2f5d1259ff1508200014dcd28bf7dcd98bf70f42f7dce36613ca46f8ff151420001466b9320e8d386603cbf7de0fbff8dcedfdfdfdff15082000146a01f7dff7de0fbbf05f0f4af9ff151420001487f86633f7dce933c18d3dc8ffe51a8d }

condition:
	$a0
}

        
