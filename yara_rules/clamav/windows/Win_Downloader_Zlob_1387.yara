rule Win_Downloader_Zlob_1387
{
strings:
	$a0 = { 76fe0013ea54f6feea141bbdca055a06a1473256cb1c72c5d7fd4e1e19f6f15b5094070b344d967ef379f5a8b7d382c43d496ce36b887ee3027776ee1b29cbb7b81a6fde81d5b7053138a05b7b0358d9776837d3dd81b61af7481cbbd054462c406b6b45fdf819dc1970177657e604f31ad08ae5e1e95f7305133a9d1607203dd6e80bfa0976742f8dc66b484e8415c743436301 }

condition:
	$a0
}

        