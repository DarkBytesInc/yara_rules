rule Win_Downloader_1035_1
{
strings:
	$a0 = { fb6136d8b1fd5dd8106c4936c2ae5ad80799ec6195c5d860d0ca5928b86d3cb8eae639b80238cbc1c6408197f68bb8eee88ddce846a2d481c9cea683eda0db56945a9fb2e9fcb2848a8700f0183ec0b10ae24355b38f55ce514f361a }

condition:
	$a0
}

        
