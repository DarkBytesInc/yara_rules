rule Win_Downloader_1317_1
{
strings:
	$a0 = { 9330fea6072c12a199ab2611d1ddef4b9f83d6cb78b47deeed8f777c5a418add64a9eeda3564554fbbb7449b25e9bc75fde6a7dc9bb74983718df4570144d3c6268535a0c552dc44addefc8321ee0aad23c2c9930dcee042fab1a60a71f79f22ba05 }

condition:
	$a0
}

        
