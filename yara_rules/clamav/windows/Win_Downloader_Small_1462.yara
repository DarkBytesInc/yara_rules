rule Win_Downloader_Small_1462
{
strings:
	$a0 = { 126164544a66843b4c2fa61c8f5eb1643166cd9105a57ae0187a3c6f20eacc3087299e5de08dd26def9f6859ae514eed1d75b233a3c482ee80dcc9e34e141db18f958cf2e831052850c4249ea675057a96870b6af55002ed173399952eefc1d0ddae094a61263772d0aa2d54599e814cf59beea51e445256eaa421549b5466975a355c8fffa259167d54f27e23effa3429a872afb3ae }

condition:
	$a0
}

        