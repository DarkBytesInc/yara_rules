rule Win_Downloader_Small_3585
{
strings:
	$a0 = { 8816687d5068018016e4b26bc7ffe9d8ba380025285cb79ee2b07d13c0051d0bc07447f8504358e0139ff8fc4fc7046168bc3b9175926965b298c514f98d4eab73019900ce3d83f80a730f68b66bc408faf3c9c3ce6c5cae0c8980077502f8008b7d08eb1a574d6a77d85773f06d444b7507c7401dc169005f4780740683c8b4405d7d74db8bb6051dcd0868 }

condition:
	$a0
}

        