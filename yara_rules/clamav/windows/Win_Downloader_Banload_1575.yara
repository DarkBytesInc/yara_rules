rule Win_Downloader_Banload_1575
{
strings:
	$a0 = { 33812710012675343035735f42484d452b2901c00a03185a7a766a7d13426761769f8011568323090e4a60667472c4e0c3ff6c30004e38f6f1bc9a879796959dea300460ac6a16996e24bbce8a25beda9fa582090340a3ce9ea7b5a2c6406b4602683bbef6d5d8de02b05c58a834fd8a3d693b96cdc0b22f9718d4993d }

condition:
	$a0
}

        