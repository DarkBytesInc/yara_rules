rule Win_Adware_Lop_139
{
strings:
	$a0 = { 78e359b368291b4d72a9b5a16ff9986b4053a48da48aba0f99a3c3a1dbddf66ef0fedf14faf60eaf2abe7269bd27b31d90c2baaf4ba3d34fe3f122112b26c4e79e0c96bbcc8d45129422773e4531a79ce4a849105ccf6b0986848eab11a3754baff8 }

condition:
	$a0
}

        
