rule Win_Downloader_Zlob_2154
{
strings:
	$a0 = { 500d58946ebd6aea49c49ddde7d824efc6d1512e1889eb5f2c619cb1a3dd9f88bac76549de4d9725686029afa69a88b1710e767f82ece19edc6cf9cdb74b093d5e207eb6cfaf6f5abd0edfdf9b9277d8ee9610dd32c8695a4a592e2a224eff7f88de98e8643b7838ae4784502d4b8f397caeed78ceb816d8a3cc21877bb9ca74 }

condition:
	$a0
}

        
