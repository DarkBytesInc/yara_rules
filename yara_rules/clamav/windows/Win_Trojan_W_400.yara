rule Win_Trojan_W_400
{
strings:
	$a0 = { 444857696e33322e53696c656e636572206279204465766961746f722f2f48415a41524450b843dcf2475803ca90898d5cc64000939389bd46c6400090899d4ac6400055905d899542c640008985 }

condition:
	$a0
}

        