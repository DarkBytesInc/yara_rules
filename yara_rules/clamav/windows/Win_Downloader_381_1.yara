rule Win_Downloader_381_1
{
strings:
	$a0 = { ae1775b8fe784e893fd607fd35ab4c12c164ac9d5c500c6ffb93451d8fc42de6dd3016d665363619aa8d2e84a8125e103bbdacfd1bdbf60c5e39b4cc738637df9cfe997e421d6ec17a2d912a99b9a68ceb3b71f63fef36cb5bbddc1c3d97 }

condition:
	$a0
}

        
