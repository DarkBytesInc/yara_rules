rule Win_Downloader_Small_1267
{
strings:
	$a0 = { 306f73427400534f465457415219455c4d5872b9281e6674bfe73e64a777bf034375728b65d97456d3bfc3696fc7f752ff996155dc4c44df3ab0c4616454f04678693665412850fe6dc7422e64dfd0144f703f905c3b4db77a421561231143381273e02849454672f26d7065525c858f2e8f78d8595c666f69da8e67bde9a8e0558bec83e40c0a5356befce99d57c5ff152823f1e864 }

condition:
	$a0
}

        