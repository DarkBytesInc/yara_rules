rule Win_Downloader_Agent_32863
{
strings:
	$a0 = { b52f3a6d22824f29b7db8dd1ef3f6110253016f0ad3e421f92309a573064d0097543ede9646352946fa65de9e7ca16d79fc4d32a5d4550659fa673d5881c }

condition:
	$a0
}

        
