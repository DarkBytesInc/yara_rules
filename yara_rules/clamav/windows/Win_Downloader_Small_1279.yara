rule Win_Downloader_Small_1279
{
strings:
	$a0 = { 746f6e652e636f6dededffff2f736f667477617265732f637261636b737773226578653310b2edf6633a5c7729646f105c1922 }

condition:
	$a0
}

        
