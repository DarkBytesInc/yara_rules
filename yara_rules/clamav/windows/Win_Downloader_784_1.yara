rule Win_Downloader_784_1
{
strings:
	$a0 = { 4bb39d093c11000fed648bb36e1dc1888b153e095d06833c06fbeee57931d233b2bd4747a06cb1a5dbc8d2d654b3e5ebe55018dba36b9fb5b50197c2b6d13a2d93a5234b0dafe29e53b0c2b16ea4ae2be1fdb41af1d600981cfb34b228b2a392f2b3b2f4ec82ebf29ec10aaeefc4641cc720f87d053b7aca6c97dcd1 }

condition:
	$a0
}

        
