rule Win_Downloader_571_1
{
strings:
	$a0 = { 80ed4dc68594f9ffff00c6858cf9ffff64c6858bf9ffff6ec6858af9ffff6980ca4680c2cdc68587f9ffff6580c12ec6858ef9ffff7780ed5d80f2adc68588f9ffff7480e246c68586f9ffff5380c6b280f58dc6858ff9ffff4c80c26280c9ad5580ee2c83ec0880c61d8b8552fbffff89042480e607 }

condition:
	$a0
}

        
