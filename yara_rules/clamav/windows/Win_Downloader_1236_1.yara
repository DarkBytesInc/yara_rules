rule Win_Downloader_1236_1
{
strings:
	$a0 = { 7505e9c8000000c685b8f9ffff41c685b6f9ffff65c685b2f9ffff6580c27180e9cec685adf9ffff45c685b9f9ffff00c685aef9ffff6ec685b1f9ffff4480e54180ed7cc685b3f9ffff76c685aaf9ffff52c685b5f9ffff6380ea6380f5bac685b4f9ffff69b104b6e7c685abf9 }

condition:
	$a0
}

        
