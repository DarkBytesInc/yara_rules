rule Win_Downloader_Small_3287
{
strings:
	$a0 = { 225f45706940f452e8bab6f840e127edeaffb4e575f21fb606ae6ce674cfe4b985955049aaa0173b98fd492250989c7b2326cbed5355de8559ede186bb28eaf6b653e2ecf82515c9f42c94ee2716474404986decb1f5ed7e94cbdfb0a5388f67fb38ee67cb6dcf926a }

condition:
	$a0
}

        
