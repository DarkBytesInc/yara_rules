rule Win_Downloader_593_1
{
strings:
	$a0 = { 69ba49cccc7caa2ee5f0faf8e939d508db154117dcd8adc1a11583bdbd15de6aaeb97747fb9884679aafdc95cfe5565958c4fed740ae396fef6ac4e8c4af3cc90da993fbffb68fe331062897fbf598d0392be6aab30701dd69603354086dc42ff346 }

condition:
	$a0
}

        
