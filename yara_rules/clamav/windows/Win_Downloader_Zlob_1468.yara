rule Win_Downloader_Zlob_1468
{
strings:
	$a0 = { 63d95b4eecbdd5570c7732818b6ae323f1071926f3dbf0ae5287f7fbf8fad64ee121c6fcc2e5ae82b46eda1f9f48ce70e489dab4ff8a39a415f5c32d6caba0ee55b73db5f8243575554641e7116aa4ac1bb655770cf90ebe26f5f6998d7eed3101eeac46a05a430d8fe671103b47b695 }

condition:
	$a0
}

        
