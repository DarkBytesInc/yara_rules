rule Win_Downloader_369_1
{
strings:
	$a0 = { c0f8ffff65c685c4f8ffff33b296c685caf8ffff0080e60680f6ccc685c2f8ffff7580cab980ca64c685c3f8ffff7480f2bbc685c9f8ffff6c80f1cfc685c1f8ffff61b56980e55fc685bef8ffff6fb61ac685c5f8ffff32c685c7f8ffff645580ca1583ec0480e28c8dbdbe }

condition:
	$a0
}

        
