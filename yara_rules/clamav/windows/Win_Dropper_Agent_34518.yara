rule Win_Dropper_Agent_34518
{
strings:
	$a0 = { c00e04acff4b6c84c075f5c36a0a586a0459bf001040008d5f216057e88e000000958b553c8b742a788d743518ad91ad50ad03c592ad03c5508bf2ad03c533d2 }

condition:
	$a0
}

        
