rule Win_Downloader_1572_1
{
strings:
	$a0 = { e8c393fbff33c0556863c8440064ff306489208d45ecba70c84400e8e877fbff8b45ece88cb7fbff84c075216a006a006890c8440068b0c844006a00e8a307fcff }

condition:
	$a0
}

        
