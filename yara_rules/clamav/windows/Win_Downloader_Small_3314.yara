rule Win_Downloader_Small_3314
{
strings:
	$a0 = { f0454311db20e14abf6b75cf35fbc47cccb688c78c9f21e7d77d324c5b9dee3adf8a92475ff47541349eaf1a3c126a2696ae4286568a47ff5341c024c05e9d5f6829a8fb45aeef1da7d79c76f243fd92b8b48dac3bc563b6cc5b309a62faf4bb8e017f7df72a1104834d3bbf0b4add8e6390d3569cb957756d60b53ae514355c4456eae07d95c789be63977dfcbc25d5e93465 }

condition:
	$a0
}

        