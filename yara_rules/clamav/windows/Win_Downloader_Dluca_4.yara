rule Win_Downloader_Dluca_4
{
strings:
	$a0 = { 6ad1043c88f39f08c1be2b90c3bdd3f232b78c726d42957cd344a971c2981e90c668d0cd4e40db62c984c3e218e35e7bb8a62d4a82e4926df0585559601bec4ad37ccc62ef7ee215268c7e0cee8a7e0310cf8807d7b3dd3fc053bd9ddcd006a44ac38cbabdaeb9 }

condition:
	$a0
}

        
