rule Win_Downloader_Time2Pay_55
{
strings:
	$a0 = { 4678b5ffb2c51a65679a2b7542af3b6951962565429a1fb0da00b68b57db4157ae01cac9dacc8933f50de7f7f4b63d155bfb7bab3688b67f4fbd5b3bf48da25f793c1c8bcf7ea5bc20b11f8d604c95b6da331e33feafc05ddf3940bd263280ce48698265ea3a998ff47b9bd3ea34ac729cf89db6f0489fcef23391 }

condition:
	$a0
}

        
