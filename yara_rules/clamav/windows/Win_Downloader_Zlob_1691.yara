rule Win_Downloader_Zlob_1691
{
strings:
	$a0 = { 4a3ec9edeaff324910eda2dd3265379ec054f5e9c3d32c62adac6e91c7d8e9ff62955c0b12b117ca3a08ce7299dea0b22056be7d82b359ab7ee914cd345acee353e98425af1156117beee4fff1980d0a382ddd791aa8a7591315 }

condition:
	$a0
}

        
