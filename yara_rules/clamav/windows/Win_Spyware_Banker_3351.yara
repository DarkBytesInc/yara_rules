rule Win_Spyware_Banker_3351
{
strings:
	$a0 = { 68cc6eb577e60a77b80b98073ab5acb02ede1739fc93c7707568409a7ef196d0b59d9a213bf0f7ad1d1ee850603bbb0e1171f45520755eafd62a5387de39c2ef1aeb9155f816ef49e45fc51de34c75ba48dd3aa929 }

condition:
	$a0
}

        
