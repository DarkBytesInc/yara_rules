rule Win_Worm_Mydoom_21
{
strings:
	$a0 = { 5278535f1d728f064e0c5e2032d3a57e064247b4b87de160cf22eb0c950358fe09a3c77813d5d8cdf3ba3ca3fe54b704478dd90bb7a4e6fe9166ec43a5a3033ab034d7896aadbe7ec4d27825ceeca96a }

condition:
	$a0
}

        
