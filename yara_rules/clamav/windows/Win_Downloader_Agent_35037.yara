rule Win_Downloader_Agent_35037
{
strings:
	$a0 = { 6eac507b4dced7294fe18dcf8b9ed5295d2183021c1407d318c3d1ef90570b3d45dfdf3747df379eac7fc2740f86837205ec303ba584832442d6e60a2fe8b0597cc5e42a7ebe3e092aece30b7bdf54481be8b0990cb1ee3674dfec1d2fe8 }

condition:
	$a0
}

        
