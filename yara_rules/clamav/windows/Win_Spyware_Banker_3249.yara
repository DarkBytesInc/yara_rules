rule Win_Spyware_Banker_3249
{
strings:
	$a0 = { b4ba04ca57702e6541626be6c411e3a8c23769f98410021038781489cedd951c6afbb9126f24bf66e3ad8e1c65af5861ed9b2c7ae71bc821bf69b475091bc5a2a5b3ba3d51bb6eb1426a019facacf79ee45797973ee6482ed08de77fe00c4052a8ecb7bf3345ac15f880e644d893be5612fdd42814f3ed94971fc9b2b487722973848871f49ea6dee8f389db }

condition:
	$a0
}

        