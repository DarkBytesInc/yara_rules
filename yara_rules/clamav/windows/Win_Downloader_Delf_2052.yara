rule Win_Downloader_Delf_2052
{
strings:
	$a0 = { fcf5c29f1ffef05fe54aea6f80897dfe95ba433a5f76ac82005bbd8abebafa002c52a120f0e9ef779cac637d47cc3ecd9458172c045e8faead6ad977a0a6bea5a9aae9f12671ef8faa4a0f36ecaf6fdcdbb8acb4b294a1f50346964f141bd62e5f2e1dd8d7bcb7b1a9bec9b7ef40fd23fb963d5affa3e58fee6914f7d41bcdb2 }

condition:
	$a0
}

        
