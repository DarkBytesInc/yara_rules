rule Win_Trojan_Bifrose_428
{
strings:
	$a0 = { 000940f6bf8cca5607a7fe1bc5aea53210613a28a5ece5c0a7bb26fb34f900f9362f72097472ef065ec9f84b3008a3861294084c3f10311234d4ad271f99e1ca634426bf2723c8253b1657c671bb354c340f7a610216703e25c1667c097e474bd1ced321951b190d95cceaa87e7c21d0e4ded4b287a995621b4b45de2a }

condition:
	$a0
}

        