rule Win_Downloader_Agent_32305
{
strings:
	$a0 = { 4d4a5143255b6b16f59251cbc367e6baab55eab1452e14e2d8240f06542624e9ca8c537d75c06e914f9c27c590728d1ad9d006498c2aca5ef6bbdc68b475de4eea9de90e9c80086d66961fe73082103faba2c995b16a57505b74aac862f0aa2623a09a065d55dbb6cd7a53fa44d120af10ddb66783b27a4a4b536ecd91203820bfb182a6a17a80fef203b17d9db18105a6458087 }

condition:
	$a0
}

        