rule Win_Trojan_Servu_77
{
strings:
	$a0 = { a9d9d38a83d0bf5660ebbed7cf8b3084a6c4cb91abe165168a231e2adcab87ccf9391e1671d34463066953a08913023fb807f08881b52a1bf5dc39687d1b7d09161af2d5aebad367b76e7ff76df1d3d453d7f95172fe24f3c52bbd9cc2dafd2fee3d0f85e8020c1a14ea57eadd832d670fafee5a470df7d93ffb1c }

condition:
	$a0
}

        
