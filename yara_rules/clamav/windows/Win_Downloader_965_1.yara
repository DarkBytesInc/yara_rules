rule Win_Downloader_965_1
{
strings:
	$a0 = { dbcbd1f47705ec333f2be2ed8fd1a543b508a4eab947609c4191e1b02560b68fbc80e00862316c69ef334f86fef26c3faaabb2d3482f7d82a1cfefbd2f60bd27ca6f2ec1f84904bd0bebcd4bb64ccd0a1fd91803f60fb28377f60ab5 }

condition:
	$a0
}

        
