rule Win_Downloader_1234_1
{
strings:
	$a0 = { 80e6c4c685b9f9ffff6380c23c80f508c685b8f9ffff65b110c685bbf9ffff00b11080c591c685b7f9ffff5280caf4c685baf9ffff74c685b6f9ffff74b52080e971c685aff9ffff6580e166c685aef9ffff4780c68ac685b3f9ffff69c685b4f9ffff65c685b2f9ffff6c80e65e }

condition:
	$a0
}

        
